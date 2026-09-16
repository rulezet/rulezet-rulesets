rule Virus_Hijack_GenPack_Backdoor_Hangup_B_345 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_345.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6390d8e28cd823dd18e5e8f7c4c709c3b6d674fb045a6a8364c4d60014e78cb"

  strings:
    $s1 = " Trade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}