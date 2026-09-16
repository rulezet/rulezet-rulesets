rule Virus_Hijack_Trojan_GenericKDZ_74550_135_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_135_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d7b35f678e9da8d78b5270daca59849e78504f20299984c4ae0bcad7f898947"

  strings:
    $s1 = "Bole z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}