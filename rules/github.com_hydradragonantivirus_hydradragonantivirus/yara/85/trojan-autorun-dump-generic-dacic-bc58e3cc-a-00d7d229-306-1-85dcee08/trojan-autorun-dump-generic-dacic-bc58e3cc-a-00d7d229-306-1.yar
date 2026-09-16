rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_306_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_306_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ce6386963f04ca8029f2b3a83dff1b7ceffaca238c5369066fd2dbc502bb035"

  strings:
    $s1 = "@Rand services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}