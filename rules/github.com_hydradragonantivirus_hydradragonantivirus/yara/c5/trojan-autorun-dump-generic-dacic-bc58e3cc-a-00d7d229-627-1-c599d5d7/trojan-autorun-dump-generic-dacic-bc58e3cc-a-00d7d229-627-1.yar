rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_627_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_627_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a46ec69e096046e802bdb8e03d8bbc75da6124c50379862ee0a3185c615fbc99"

  strings:
    $s1 = "$6your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}