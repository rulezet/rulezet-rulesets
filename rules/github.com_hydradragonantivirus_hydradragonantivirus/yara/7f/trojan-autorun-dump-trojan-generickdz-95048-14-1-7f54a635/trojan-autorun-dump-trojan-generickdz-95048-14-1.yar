rule Trojan_Autorun_Dump_Trojan_GenericKDZ_95048_14_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "137786bdff66ed17ad0ce3545f78d0456371ac6e04e8c8c801746cf26df53574"

  strings:
    $s1 = "dand hardware systems to the applications programs and (c) building extensions to applications programs. You shall not" fullword ascii
    $s2 = "the same degree of care to safeguard the confidentiality of the TRMs as you exercise to safeguard the confidenti`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}