rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_565_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_565_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f07ba7c3e73e437af5ee37c508789fe22861bc20dce64e3c95a79d572e551cd"

  strings:
    $s1 = "ITrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}