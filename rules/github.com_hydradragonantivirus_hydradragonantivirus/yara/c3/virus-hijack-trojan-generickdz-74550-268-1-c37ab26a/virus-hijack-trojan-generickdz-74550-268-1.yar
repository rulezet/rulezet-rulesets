rule Virus_Hijack_Trojan_GenericKDZ_74550_268_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_268_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef8c4c04aa3743caaa78451765b58b191be9fdcddd3a15b90f483585d46e923d"

  strings:
    $s1 = "p!WAkA" fullword ascii
    $s2 = "de[tHOw" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}