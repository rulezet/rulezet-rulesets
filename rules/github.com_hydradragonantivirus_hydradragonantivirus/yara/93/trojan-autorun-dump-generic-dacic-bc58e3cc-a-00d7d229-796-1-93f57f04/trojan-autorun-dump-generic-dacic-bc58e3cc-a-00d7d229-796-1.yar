rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_796_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_796_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74a94a11bc854a826d536af3cd3411ca31dae354859a8739badf68d8455ab45c"

  strings:
    $s1 = "qyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}