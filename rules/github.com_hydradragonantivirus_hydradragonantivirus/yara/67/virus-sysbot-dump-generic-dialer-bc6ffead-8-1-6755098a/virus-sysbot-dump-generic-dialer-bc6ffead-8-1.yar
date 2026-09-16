rule Virus_Sysbot_Dump_Generic_Dialer_BC6FFEAD_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BC6FFEAD_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "101cfd6845ea6ed3416e33492454e54f5218592a034d5fc59d26e403a488acd9"

  strings:
    $s1 = "LorS@8" fullword ascii
    $s2 = "Teth`m" fullword ascii
    $s3 = "Q<maBi" fullword ascii
    $s4 = "RusT,:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}