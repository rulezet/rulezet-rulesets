rule Virus_Hijack_Trojan_GenericKDZ_105924_63_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_63_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44a4a033c6c0ab5df1c5814a8b429c1915090b651983f4ae2bf5fda476e5796a"

  strings:
    $s1 = "Peon i" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}