rule Virus_Hijack_GenPack_Backdoor_Hangup_B_441 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_441.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee56433fa6ab5d46da16d0d2bffa17aba4baf4f4ebcb1778cf3657f2718cc6d1"

  strings:
    $s1 = "$zTrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}