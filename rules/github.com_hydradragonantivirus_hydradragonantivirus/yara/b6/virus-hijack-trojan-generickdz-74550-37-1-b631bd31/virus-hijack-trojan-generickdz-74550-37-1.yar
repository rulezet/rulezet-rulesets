rule Virus_Hijack_Trojan_GenericKDZ_74550_37_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_37_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30fea97f1576a1c2196e233519dc3992d423a07065850240022a0d9c019dadef"

  strings:
    $s1 = ".[TaRA#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}