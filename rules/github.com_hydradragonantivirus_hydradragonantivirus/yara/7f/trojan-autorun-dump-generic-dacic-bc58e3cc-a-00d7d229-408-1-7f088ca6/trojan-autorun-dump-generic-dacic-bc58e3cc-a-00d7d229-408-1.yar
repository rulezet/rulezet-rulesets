rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_408_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_408_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e132e87757bd3b5fdf08d8b6977e46a973fb53d2429d1bc2d8c8ca745962a2c5"

  strings:
    $s1 = "RYou may temporarily download the fonts to a prin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}