rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_206_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_206_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50dc93c896458d43db4c4d1ca0aebce34abd357598f9aa78d1003e5bfe3ceeca"

  strings:
    $s1 = "Root$7I" fullword ascii
    $s2 = "System$7I" fullword ascii
    $s3 = "Monochrome(" fullword ascii
    $s4 = "Count<\\G" fullword ascii
    $s5 = "Count,lG" fullword ascii
    $s6 = "Position$7I" fullword ascii
    $s7 = "Current IK" fullword ascii
    $s8 = "Owner$7I" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}