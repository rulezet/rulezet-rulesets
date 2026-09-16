rule Virus_Sysbot_Dump_Generic_Dialer_BEBD122F_12 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BEBD122F_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d9b1fcaf056b413df26be78d9999c5081fca241b473196f1a8b175edb51ff09"

  strings:
    $s1 = ":EBoE`" fullword ascii
    $s2 = "}rEtCH" fullword ascii
    $s3 = "n>muNg" fullword ascii
    $s4 = "y:BaFf" fullword ascii
    $s5 = "FIlO}R" fullword ascii
    $s6 = "w8{B`raNE" fullword ascii
    $s7 = "TALd ~" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}