rule Virus_Hijack_Gen_Trojan_ShellObject__WZ_aCIJdog_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.@WZ@aCIJdog_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48b7c77fb121e497c16cd498383af53166b4c9ad8a9b51bb890a090e83844ffd"

  strings:
    $s1 = "^qfunctionality of the programs. You have 30 days from the delivery date to evaluate these programs. If you decide to use any" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}