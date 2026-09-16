rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_211_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_211_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82288b7e8104a0143320ded6d208837fdacbd5046c0a1e064297a7055b5b8f8e"

  strings:
    $s1 = "e%KUDu" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}