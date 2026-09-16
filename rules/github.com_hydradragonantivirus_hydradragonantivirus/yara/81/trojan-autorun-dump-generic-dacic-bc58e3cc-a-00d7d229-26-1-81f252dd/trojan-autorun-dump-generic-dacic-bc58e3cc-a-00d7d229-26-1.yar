rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_26_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_26_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91d6a410063b5041c1752d76b2ac56dfa932e28bd29009f5fbbf83cab02b975b"

  strings:
    $s1 = "Labor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}