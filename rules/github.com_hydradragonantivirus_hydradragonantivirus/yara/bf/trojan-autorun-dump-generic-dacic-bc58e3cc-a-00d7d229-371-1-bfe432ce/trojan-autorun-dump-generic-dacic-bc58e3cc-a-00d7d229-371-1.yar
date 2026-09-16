rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_371_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_371_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9a4ba688008ffa97680bcad2a4274fe7cf6f91ac3f9147fd1d16dffa68c5038"

  strings:
    $s1 = "-!iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}