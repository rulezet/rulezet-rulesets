rule Trojan_Danger_Trojan_GenericKD_67166905_71_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_71_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1acd4e729c1552b958122ab369501fe16f202baf5eba1e0c52fbda2c836b72da"

  strings:
    $s1 = "L<CrAG>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}