rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_522_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_522_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dae0b59ce3d6d651f56f941dfdadb70e1e5f8ba2ddf89cc0aa1226dcd87e8737"

  strings:
    $s1 = "Drthe licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}