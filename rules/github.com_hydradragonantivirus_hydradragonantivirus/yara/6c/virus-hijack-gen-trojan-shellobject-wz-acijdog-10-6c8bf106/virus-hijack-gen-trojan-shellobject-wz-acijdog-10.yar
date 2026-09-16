rule Virus_Hijack_Gen_Trojan_ShellObject__WZ_aCIJdog_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.@WZ@aCIJdog_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07ce2b9e3bf01ddac588096d562def90761a093a1bd5ef4a59301867ea6587cd"

  strings:
    $s1 = "!}functionality of the programs. You have 30 days from the delivery date to evaluate these programs. If you decide to use any" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}