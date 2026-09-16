rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_722_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_722_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2dde5bcf29695298365a2c9f3f1843bb4cf4435564581271d6c27cabc1d07de"

  strings:
    $s1 = "Esoftware manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}