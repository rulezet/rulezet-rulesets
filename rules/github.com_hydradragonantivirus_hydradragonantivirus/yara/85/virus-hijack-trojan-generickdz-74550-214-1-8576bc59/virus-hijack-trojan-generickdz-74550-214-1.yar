rule Virus_Hijack_Trojan_GenericKDZ_74550_214_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_214_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b35b0944b2a62a2b13c7d2aaed13a7ce64db74aa821ed51121d4a40bf71b6e2"

  strings:
    $s1 = "ALeC`op" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}