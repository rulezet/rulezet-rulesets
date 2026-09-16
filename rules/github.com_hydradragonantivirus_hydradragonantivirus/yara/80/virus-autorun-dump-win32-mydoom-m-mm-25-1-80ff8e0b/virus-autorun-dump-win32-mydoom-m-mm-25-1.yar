rule Virus_Autorun_Dump_Win32_Mydoom_M_mm_25_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Dump.Win32.Mydoom.M@mm_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a365fa959369919af757b979ce20fa868b939d7d784101c4432b524f07a0363"

  strings:
    $s1 = "Uninstall Ruby 3.2.2-1-x64.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}