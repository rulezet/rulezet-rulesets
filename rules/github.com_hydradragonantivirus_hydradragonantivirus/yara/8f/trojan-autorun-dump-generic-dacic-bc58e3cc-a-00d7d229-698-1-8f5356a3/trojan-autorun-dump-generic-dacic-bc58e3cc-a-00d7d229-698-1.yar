rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_698_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_698_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcc689721290ad507ac174372fa1f61dce63f67b71004f027777b00b4a6bd002"

  strings:
    $s1 = "-dcreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}