rule quantum_license {
  meta:
    description = "IcedID - file license.dat"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com/2022/04/25/quantum-ransomware/"
    date        = "2022-04-24"
    hash1       = "84f016ece77ddd7d611ffc0cbb2ce24184aeee3a2fdbb9d44d0837bc533ba238"

  strings:
    $s1  = "W* |[h" fullword ascii
    $s2  = "PSHN,;x" fullword ascii
    $s3  = "ephu\"W" fullword ascii
    $s4  = "LwUw9\\" fullword ascii
    $s5  = "VYZP~pN," fullword ascii
    $s6  = "eRek?@" fullword ascii
    $s7  = "urKuEqR" fullword ascii
    $s8  = "1zjWa{`!" fullword ascii
    $s9  = "YHAV{tl" fullword ascii
    $s10 = "bwDU?u" fullword ascii
    $s11 = "SJbW`!W" fullword ascii
    $s12 = "BNnEx1k" fullword ascii
    $s13 = "SEENI3=" fullword ascii
    $s14 = "Bthw?:'H*" fullword ascii
    $s15 = "NfGHNHC" fullword ascii
    $s16 = "xUKlrl'>`" fullword ascii
    $s17 = "gZaZ^;Ro2" fullword ascii
    $s18 = "JhVo5Bb" fullword ascii
    $s19 = "OPta)}$" fullword ascii
    $s20 = "cZZJoVB" fullword ascii

  condition:
    uint16(0) == 0x44f8 and filesize < 1000KB and
    8 of them
}