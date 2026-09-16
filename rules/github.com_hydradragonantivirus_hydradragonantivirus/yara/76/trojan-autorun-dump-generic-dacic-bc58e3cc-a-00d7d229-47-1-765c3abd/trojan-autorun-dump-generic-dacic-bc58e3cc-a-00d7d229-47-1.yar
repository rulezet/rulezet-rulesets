rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_47_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_47_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbca657a77a9e700f14e2df0bbb18f3853617895ec44fdd4b6c7bc4993d4c221"

  strings:
    $s1 = "Oracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}