rule Virus_Hijack_Trojan_GenericKDZ_105924_451_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_451_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38c2302a545cc2d5a07d6c79279f6c9e2c60cb62ca303aa85e95c954002b6b49"

  strings:
    $s1 = "@grEE:" fullword ascii
    $s2 = "@,HaLO" fullword ascii
    $s3 = "X![fish" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}