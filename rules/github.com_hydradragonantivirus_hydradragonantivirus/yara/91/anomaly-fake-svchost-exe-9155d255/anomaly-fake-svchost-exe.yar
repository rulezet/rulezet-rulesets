import "pe"
rule Anomaly_Fake_svchost_exe {
  meta:
    author      = "albertzsigovits"
    description = "Anomaly rule for finding fake svchost.exe"

  condition:
    uint16be(0) == 0x4D5A
    and pe.version_info["CompanyName"] contains "Microsoft Corporation"
    and
    (pe.version_info["InternalName"] contains "svchost"
      or pe.version_info["OriginalFilename"] contains "svchost")
    and not
    (pe.version_info["InternalName"] matches /svchost.exe/i
      or pe.version_info["OriginalFilename"] matches /svchost.exe/i)
}