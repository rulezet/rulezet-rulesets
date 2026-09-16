rule Virus_Hijack_Trojan_GenericKDZ_74550_45_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_45_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43a6ca7d3bbcd5b7358a2603cd9d082d9eda2cdea54cf420ded954d779d74c21"

  strings:
    $s1 = "R#APIO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}