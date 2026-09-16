rule Virus_Hijack_Gen_Trojan_ShellObject__WZ_aCIJdog_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.@WZ@aCIJdog_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "128f68801bdd1620c474bca7b363b77df30e1dd5608021591c5ceddec7e27f65"

  strings:
    $s1 = "LBuilt using an evaluation version of {smartassembly}. Cannot be distributed." fullword ascii
    $s2 = " exile" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}