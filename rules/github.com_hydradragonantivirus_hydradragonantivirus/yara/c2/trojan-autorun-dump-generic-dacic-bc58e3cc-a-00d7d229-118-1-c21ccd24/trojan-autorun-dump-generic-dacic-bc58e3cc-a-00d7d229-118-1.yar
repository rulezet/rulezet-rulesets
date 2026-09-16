rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_118_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_118_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d37752b6849aac66cbf601f767ccbf1e18aa1adb8875c501c208d8cffe8438af"

  strings:
    $s1 = "5active employee population and not the number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}