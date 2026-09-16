rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_99_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_99_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f00166bce58bf45605467b5c3105e3ba0a3d96bec55d23625e8f8edacc44b32"

  strings:
    $s1 = "7dcreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}