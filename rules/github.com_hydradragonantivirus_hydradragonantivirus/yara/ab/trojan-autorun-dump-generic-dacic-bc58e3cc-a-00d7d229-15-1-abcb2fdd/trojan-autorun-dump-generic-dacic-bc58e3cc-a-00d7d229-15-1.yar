rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_15_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59b3993d2cf145a593a495dd32f66d1f4e9f9ee41460e3048ea70e85265b5928"

  strings:
    $s1 = "PRLabor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}