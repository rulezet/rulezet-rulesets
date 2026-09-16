rule Virus_Autorun_Win32_Neshta_A_47 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_47.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c59f0f33d08cfc39f9f733287cbe09ebd91df271077853cf8a8b7e25e8422231"

  strings:
    $s1 = "GCC: (Rev11, Built by MSYS2 project) 12.2.0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}