rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_212_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_212_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92a1adc462adbf747ec142eeeab2dc55aa0e809c678116fad23ea8c8a80ad1cf"

  strings:
    $s1 = "e%KUDu" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}