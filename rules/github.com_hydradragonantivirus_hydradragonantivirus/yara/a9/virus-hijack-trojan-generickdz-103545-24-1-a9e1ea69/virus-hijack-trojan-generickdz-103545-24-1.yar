rule Virus_Hijack_Trojan_GenericKDZ_103545_24_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_24_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "038052e45fec0dc10de3cf1a0e339b65d0d5a7c6fb457186236441c81d5effac"

  strings:
    $s1 = "sCOw{Mh6O" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}