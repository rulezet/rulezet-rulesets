rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_261_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_261_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b45460e37260b11092efaa0a26b78a6448b5f23843ab76515018b19263185f12"

  strings:
    $s1 = "System KD" fullword ascii
    $s2 = "System<2I" fullword ascii
    $s3 = "Count@!G" fullword ascii
    $s4 = "List$iH" fullword ascii
    $s5 = "Handle(;E" fullword ascii
    $s6 = "List@:I" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}