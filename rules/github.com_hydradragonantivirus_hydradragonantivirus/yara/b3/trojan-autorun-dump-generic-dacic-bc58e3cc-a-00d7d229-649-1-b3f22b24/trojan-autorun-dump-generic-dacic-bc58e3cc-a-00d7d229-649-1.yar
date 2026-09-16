rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_649_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_649_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6627cc9fa0bbc19f2e0d213aec3da506f5da8059986ed1c925a447973d8a96e5"

  strings:
    $s1 = "0software manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}