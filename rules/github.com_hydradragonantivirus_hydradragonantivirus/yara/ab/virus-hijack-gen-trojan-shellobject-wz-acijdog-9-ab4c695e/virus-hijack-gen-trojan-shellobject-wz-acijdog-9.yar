rule Virus_Hijack_Gen_Trojan_ShellObject__WZ_aCIJdog_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.@WZ@aCIJdog_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5786c372e8647d9dc0539625b70602dac12db6bffc91d6e6d89157508f4032fd"

  strings:
    $s1 = "|functionality of the programs. You have 30 days from the delivery date to evaluate these programs. If you decide to use any" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}