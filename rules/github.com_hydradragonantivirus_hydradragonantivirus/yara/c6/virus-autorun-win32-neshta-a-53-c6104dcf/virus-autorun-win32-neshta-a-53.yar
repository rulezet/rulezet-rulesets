rule Virus_Autorun_Win32_Neshta_A_53 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_53.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5af44e63a7e184d48085678c2171fc5dcfb7ac024953558eb67424c9c0d69e7"

  strings:
    $s1 = "0Copyright 2018. Hancom Inc. All rights reserved." fullword ascii
    $s2 = "Copyright 2018. Hancom Inc. All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}