rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_358_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_358_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd68ef86dc602d08053dc5292e299a532151c081d3b59d49abc35c29ab4526e0"

  strings:
    $s1 = "^EiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}