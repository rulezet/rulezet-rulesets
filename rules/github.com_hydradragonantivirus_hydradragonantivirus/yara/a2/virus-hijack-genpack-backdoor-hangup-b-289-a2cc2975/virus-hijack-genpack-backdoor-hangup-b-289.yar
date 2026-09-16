rule Virus_Hijack_GenPack_Backdoor_Hangup_B_289 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_289.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84a7562db9b9e3f9063e258fbef84e30dbde95c3ed2b5711c488d81bcc778b7b"

  strings:
    $s1 = ".ZTrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}