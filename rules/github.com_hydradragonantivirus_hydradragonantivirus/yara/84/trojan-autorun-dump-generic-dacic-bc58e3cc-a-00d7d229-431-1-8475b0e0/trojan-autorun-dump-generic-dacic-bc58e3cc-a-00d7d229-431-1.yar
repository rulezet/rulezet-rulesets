rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_431_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_431_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39f7908d7ccecba89f4b8d909ec59644749ca71e9d32ba89fb5f9fb9fb2c8e9b"

  strings:
    $s1 = "MiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}