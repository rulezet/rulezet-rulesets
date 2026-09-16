rule Virus_Hijack_GenPack_Backdoor_Hangup_B_475 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_475.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6f3cef069f4ef435d063f53ddf54092b7ae3b6879010655538cf8f56d55f755"

  strings:
    $s1 = "(lTrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}