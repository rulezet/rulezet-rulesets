rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_64_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_64_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e11e38819cadccf65873474cd77dd646c7d2f85bee7df56ce860e2cad9a2c046"

  strings:
    $s1 = "M]create this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}