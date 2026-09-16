rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_3_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "138fc602a4ca1c5acd8bca12350cdeb57f68a4bb18f71683cd4ec953e7ec4c10"

  strings:
    $s1 = "!Workshop" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}