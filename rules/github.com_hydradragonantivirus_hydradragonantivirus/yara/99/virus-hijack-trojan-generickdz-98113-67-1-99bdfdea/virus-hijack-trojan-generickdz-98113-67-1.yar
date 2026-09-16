rule Virus_Hijack_Trojan_GenericKDZ_98113_67_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_67_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60c840fab06afd8aa73786bed43eebc681ef5dcc3b9255e62894cecbb67514ac"

  strings:
    $s1 = ":DIcE,z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}