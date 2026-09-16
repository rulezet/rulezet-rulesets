rule Virus_Hijack_Trojan_GenericKDZ_99416_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d95a6b7242052b83802cb06b682c1601d1ff745685d8acbbc82ca3a9fd7f4857"

  strings:
    $s1 = "rAKh ZFz" fullword ascii
    $s2 = "VETa?m" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}