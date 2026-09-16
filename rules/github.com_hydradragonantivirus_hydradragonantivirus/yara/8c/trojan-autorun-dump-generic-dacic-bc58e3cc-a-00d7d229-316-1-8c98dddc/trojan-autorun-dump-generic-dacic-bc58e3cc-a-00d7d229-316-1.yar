rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_316_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_316_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aff6df1296b960636128e9f4da5364b6813331cfb3d3abcaefaf8c5114d8e262"

  strings:
    $s1 = "~kare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}