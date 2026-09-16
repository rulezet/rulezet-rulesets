rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_792_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_792_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da101c0b7ebafef4bb2979d546e83b8dd113a24b9b2f527e38e9f67aa752f3ae"

  strings:
    $s1 = "[and hardware systems to the applications programs and (c) building extensions to applications programs. You shall not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}