rule Virus_Hijack_Gen_Trojan_ShellObject_RAZ_aCEmdoo_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.RAZ@aCEmdoo_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "362f8473b6d793ed902c9cb56584ff9d93a537d625e162fae63f8195e911f87e"

  strings:
    $s1 = "OxYL`)O" fullword ascii
    $s2 = "Enam>E$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}