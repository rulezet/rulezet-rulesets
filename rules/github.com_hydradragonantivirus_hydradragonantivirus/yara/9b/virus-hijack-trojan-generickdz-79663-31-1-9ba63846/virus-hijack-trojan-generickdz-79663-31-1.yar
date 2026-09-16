rule Virus_Hijack_Trojan_GenericKDZ_79663_31_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_31_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cea4b4b24ff37871c4eb3ae816ea4038d431bacdbcbc5c78b1d25d1b99879ddf"

  strings:
    $s1 = "rb,kULa" fullword ascii
    $s2 = "sopH{J" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}