rule Virus_Hijack_Trojan_GenericKDZ_103285_178 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_178.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7b4847652f82ef22ef889af21d453c9e83517382c90bab9838db1ca2da018dd"

  strings:
    $s1 = "aJAb>bATh" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}