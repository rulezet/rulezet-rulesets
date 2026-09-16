rule Virus_Hijack_Trojan_GenericKDZ_99416_41_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_41_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c79df0e1aafcbc98b67ff3689fea4784cca6d20767d80e11910176894ec65e6"

  strings:
    $s1 = "2,WooM" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}