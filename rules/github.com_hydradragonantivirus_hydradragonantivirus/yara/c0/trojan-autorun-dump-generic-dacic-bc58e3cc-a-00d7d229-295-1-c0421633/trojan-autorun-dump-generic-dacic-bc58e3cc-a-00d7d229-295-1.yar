rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_295_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_295_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21437f6c2a2fbe0938f77e2cfc939420d5f77102cc34d219c8e693365308217e"

  strings:
    $s1 = "XiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}