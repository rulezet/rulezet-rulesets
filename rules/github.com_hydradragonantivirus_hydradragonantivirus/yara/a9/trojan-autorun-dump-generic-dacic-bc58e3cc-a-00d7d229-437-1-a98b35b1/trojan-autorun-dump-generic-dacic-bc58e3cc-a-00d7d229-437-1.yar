rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_437_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_437_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3cf2049c3b12803bcc3eae5f9ba347203db0b103d1fb8a6264273b155197590"

  strings:
    $s1 = "aLabor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}