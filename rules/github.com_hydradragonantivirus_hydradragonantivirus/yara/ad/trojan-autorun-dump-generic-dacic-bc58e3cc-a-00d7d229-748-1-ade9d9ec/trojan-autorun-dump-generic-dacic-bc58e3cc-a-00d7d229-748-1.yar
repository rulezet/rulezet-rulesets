rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_748_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_748_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4abe90c12032b7687b04c3f26ae18a55d9057f4622d74f0dc48be91dd2845b19"

  strings:
    $s1 = "JTrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}