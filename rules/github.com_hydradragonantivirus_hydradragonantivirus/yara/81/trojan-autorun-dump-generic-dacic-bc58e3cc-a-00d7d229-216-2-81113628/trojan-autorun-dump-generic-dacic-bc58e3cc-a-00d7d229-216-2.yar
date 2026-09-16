rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_216_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_216_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e1bb7c937175e469d5498b6419952b405597e6d752a1704ce64ddecd4eb02b1"

  strings:
    $s1 = "\\UvR@hemp{b" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}