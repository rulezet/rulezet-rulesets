rule Virus_Hijack_Trojan_GenericKDZ_105924_479_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_479_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75a62fa07bc82bc27db24d2e4b9024f2f40c89c7142bac54eafdeeb33b598e42"

  strings:
    $s1 = "cOoP>P" fullword ascii
    $s2 = "P;ApEX" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}