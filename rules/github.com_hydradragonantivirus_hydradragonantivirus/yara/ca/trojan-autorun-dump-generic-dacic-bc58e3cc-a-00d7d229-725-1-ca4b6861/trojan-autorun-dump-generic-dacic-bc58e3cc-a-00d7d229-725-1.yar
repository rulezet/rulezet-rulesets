rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_725_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_725_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "123759d79d495a937a785c3d64daf81b3a978dac47a22aaba480a61c52f1c647"

  strings:
    $s1 = "IA. Agreement Definitions" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}