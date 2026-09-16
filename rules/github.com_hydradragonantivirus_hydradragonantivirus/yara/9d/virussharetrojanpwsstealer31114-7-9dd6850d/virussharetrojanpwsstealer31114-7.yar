rule VirusShareTrojanPWSStealer31114_7 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanPWSStealer31114_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92bf7a9cf9e9376e3844f039ac6b8fd577ec5de2720ae5cd17263ad179084500"

  strings:
    $s1 = "Stibnite Alkane Inc.1" fullword ascii
    $s2 = "Riband" fullword ascii
    $s3 = "j&aTEF" fullword ascii
    $s4 = " macK)" fullword ascii
    $s5 = "Wi{sLiD" fullword ascii
    $s6 = "K)frIz" fullword ascii
    $s7 = "Rich@!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}