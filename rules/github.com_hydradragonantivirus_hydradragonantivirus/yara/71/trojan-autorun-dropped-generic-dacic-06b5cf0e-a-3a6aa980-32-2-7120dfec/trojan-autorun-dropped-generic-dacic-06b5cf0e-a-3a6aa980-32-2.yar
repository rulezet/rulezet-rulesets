rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_32_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_32_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0cca04411fb0efd4b26397941ce3ff01c7f021efd79983431234a3f27d34409c"

  strings:
    $s1 = "jg0[%:GYTE" fullword ascii
    $s2 = ")?TrIo," fullword ascii
    $s3 = "`UPlA{" fullword ascii
    $s4 = "PInA`N" fullword ascii
    $s5 = "h:RaDA" fullword ascii
    $s6 = "gUrT$5" fullword ascii
    $s7 = "``KaHA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}