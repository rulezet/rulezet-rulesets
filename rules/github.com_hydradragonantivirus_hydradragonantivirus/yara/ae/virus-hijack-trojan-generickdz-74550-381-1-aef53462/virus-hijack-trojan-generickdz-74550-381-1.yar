rule Virus_Hijack_Trojan_GenericKDZ_74550_381_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_381_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "741918c3ef50a771a2d077c17bc6acd3f549065719fbb43c221e2c81ee4a87ea"

  strings:
    $s1 = "aGOn),*" fullword ascii
    $s2 = ";Rede>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}