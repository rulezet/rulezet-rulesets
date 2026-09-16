rule Virus_Hijack_Trojan_GenericKDZ_105924_209_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_209_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a15f5dc57017ef1cf8c0480ef03c9246d2cc5180f522818116a1f27c348c524"

  strings:
    $s1 = "<description>Internet Backgammon</description>" fullword ascii
    $s2 = "  -t, --tabs=LIST     use comma separated list of explicit tab positions" fullword ascii
    $s3 = "Internet Backgammon" fullword wide
    $s4 = "  -i, --initial       do not convert tabs after non blanks" fullword ascii
    $s5 = "  -t, --tabs=NUMBER   have tabs NUMBER characters apart, not 8" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}