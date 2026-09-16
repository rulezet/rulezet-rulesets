rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_70_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_70_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c8a4449a890bf590c5cabba0748148858923af944cda94063741864b64ca71c"

  strings:
    $s1 = "m\\the licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}