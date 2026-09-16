rule Virus_Hijack_Trojan_GenericKDZ_74550_222_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_222_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ee6a6990ea67ed56e5a30c608b3cb2884b9810a56ba3abb0522b9575eabe779"

  strings:
    $s1 = "gYRE:_5d" fullword ascii
    $s2 = "Firn,/d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}