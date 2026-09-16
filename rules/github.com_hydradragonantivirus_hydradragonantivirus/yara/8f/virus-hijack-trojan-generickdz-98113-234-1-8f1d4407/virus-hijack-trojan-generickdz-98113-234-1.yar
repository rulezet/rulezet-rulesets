rule Virus_Hijack_Trojan_GenericKDZ_98113_234_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_234_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30578a6fd8b18214542c05abbb510cea0e837f3050fe3ce159b83d1f6ea85f59"

  strings:
    $s1 = "ASsE<2" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}