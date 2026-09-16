rule Virus_Autorun_Dump_Win32_Mydoom_M_mm_147_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Dump.Win32.Mydoom.M@mm_147_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85fe3d527eeb7a88759f4d586400518094d4c43a523e87b421446c7ee1a5896d"

  strings:
    $s1 = "Uninstall Ruby 3.2.2-1-x64.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}