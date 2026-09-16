rule Trojan_Danger_Trojan_GenericKD_72853156_496_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_496_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4c8c048519e59b7cda2e92ca4d4f3df2ffa4a10b0730d52f20644c8cd15b4a6"

  strings:
    $s1 = "t+ IntegratX with SO(" fullword ascii
    $s2 = "Termin*b" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}