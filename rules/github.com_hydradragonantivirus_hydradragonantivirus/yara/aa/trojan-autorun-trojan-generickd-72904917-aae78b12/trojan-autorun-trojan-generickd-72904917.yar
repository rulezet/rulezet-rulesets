rule Trojan_Autorun_Trojan_GenericKD_72904917 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72904917.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8f63a152de87829e3d031f4848f893c539c3c7e28918ee8139ac6c86abaef06"

  strings:
    $s1 = "YVisible in Windows API, but not in MFT or directory index." fullword wide
    $s2 = "W::$DATA" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}