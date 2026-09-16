rule Virus_Hijack_Trojan_GenericKDZ_105924_555_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_555_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb977429cacfa33905cf6bc0ba4b2e4e795a5249dd022027f33f7e8dd8d83e57"

  strings:
    $s1 = "p#moat;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}