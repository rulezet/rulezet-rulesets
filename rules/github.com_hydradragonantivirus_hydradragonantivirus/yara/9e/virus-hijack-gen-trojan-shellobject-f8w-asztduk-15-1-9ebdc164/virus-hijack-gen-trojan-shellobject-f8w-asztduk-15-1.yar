rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aSZtDuk_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "635785b32486b08783943e5c6a2570ed34dc0de20521244d0b35a6a33b7e6272"

  strings:
    $s1 = "C:\\DOCUME~1\\RODBEH~1\\LOCALS~1\\Temp\\Temporary Directory 5 for Label_0BM57Y4APYI54VU[1].zip\\Label_368_09112013_JDSL.exe" fullword wide
    $s2 = "Hello word" fullword ascii
    $s3 = "><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security>" fullword ascii
    $s4 = " <?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersi" ascii
    $s5 = " <?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersi" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}