rule Virus_Hijack_GenPack_Backdoor_Hangup_B_236 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_236.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89ec1c57a25f762f69f462ff0f39a37662598dc897db2232bfb6f0ebb36c32ca"

  strings:
    $s1 = "MvTrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}