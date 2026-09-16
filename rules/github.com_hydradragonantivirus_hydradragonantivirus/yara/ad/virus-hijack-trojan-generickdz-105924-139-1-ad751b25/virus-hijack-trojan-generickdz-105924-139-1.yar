rule Virus_Hijack_Trojan_GenericKDZ_105924_139_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_139_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "976b27e79757b428673081cc5ef2405ac1b31bd68976bd896a4e4c2ca5c1dfe8"

  strings:
    $s1 = "LBuilt using an evaluation version of {smartassembly}. Cannot be distributed." fullword ascii
    $s2 = " exile" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}