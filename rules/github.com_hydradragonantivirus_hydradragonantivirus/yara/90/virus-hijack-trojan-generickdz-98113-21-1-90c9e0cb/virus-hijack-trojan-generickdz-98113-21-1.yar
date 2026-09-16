rule Virus_Hijack_Trojan_GenericKDZ_98113_21_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_21_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "482bbdd1b3410a677e05ac578b1a52fd690b81d7816bbe5b9a8c93987a6ba2b8"

  strings:
    $s1 = "=%tcHU" fullword ascii
    $s2 = "(TAnk(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}