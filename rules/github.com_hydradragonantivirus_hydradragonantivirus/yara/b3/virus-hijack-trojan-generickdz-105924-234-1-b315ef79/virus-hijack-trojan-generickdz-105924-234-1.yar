rule Virus_Hijack_Trojan_GenericKDZ_105924_234_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_234_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b85ea38eddf3721f1b30f91a680dfca90416ff08454d55f612b650d90dd97398"

  strings:
    $s1 = "exceeded maximum command-line args %d" fullword wide
    $s2 = "%s : fatal error -: " fullword wide
    $s3 = "  -t, --tabs=LIST     use comma separated list of explicit tab positions" fullword ascii
    $s4 = "%1 is an unimplemented method" fullword wide
    $s5 = "  -i, --initial       do not convert tabs after non blanks" fullword ascii
    $s6 = "  -t, --tabs=NUMBER   have tabs NUMBER characters apart, not 8" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}