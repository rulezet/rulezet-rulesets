rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_525_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_525_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1947066e51187d941275e6c57c57851af5445d62f4811b6268600238e3d17c01"

  strings:
    $s1 = "mTrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}