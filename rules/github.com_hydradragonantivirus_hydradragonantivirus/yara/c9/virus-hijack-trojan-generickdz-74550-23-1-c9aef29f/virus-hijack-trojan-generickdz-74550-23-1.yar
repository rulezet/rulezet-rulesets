rule Virus_Hijack_Trojan_GenericKDZ_74550_23_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_23_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fca932ce0708d18349bbec34b35f96da1364bb4a9b11308eef29af6bd11503e6"

  strings:
    $s1 = "AnnA)q+" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}