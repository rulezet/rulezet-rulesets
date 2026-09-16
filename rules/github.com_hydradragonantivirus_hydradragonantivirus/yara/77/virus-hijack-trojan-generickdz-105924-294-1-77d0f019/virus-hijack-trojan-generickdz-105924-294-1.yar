rule Virus_Hijack_Trojan_GenericKDZ_105924_294_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_294_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "476f5b0e84c2949dacf78d7d3a9b3e0ea9faa7cf9ff632ff0c69483cc760e8a9"

  strings:
    $s1 = " mOHo{p" fullword ascii
    $s2 = "}}Heck" fullword ascii
    $s3 = "}^*RooK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}