rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_342_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_342_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d5e2387d4a6027dac35c64a818366493586dbcda81359aa22ab92b4702ff0c6"

  strings:
    $s1 = "TIEn?H-" fullword ascii
    $s2 = "@kare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}