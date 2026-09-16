rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_7_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce100dd374334e127a606b7370ad7dde1365658092dcdfc0e5e1f597e649f826"

  strings:
    $s1 = ">the licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}