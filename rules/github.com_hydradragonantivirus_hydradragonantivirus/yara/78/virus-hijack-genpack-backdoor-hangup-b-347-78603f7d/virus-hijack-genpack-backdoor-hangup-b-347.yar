rule Virus_Hijack_GenPack_Backdoor_Hangup_B_347 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_347.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "070b994fe9aec81c234157951cf2cf70b62a140fd692de9716dad4266d19945c"

  strings:
    $s1 = "dTrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}