rule Virus_Hijack_Trojan_GenericKDZ_74550_343_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_343_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8df132ee632d3dbdee2b039c28b177377d9deb0a205b541e7a31398b647bde42"

  strings:
    $s1 = "&MorA$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}