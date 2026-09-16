rule Virus_Hijack_GenPack_Backdoor_Hangup_B_338 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_338.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e819bd2ec6aef62afb2f97fd3207f00b6b7c0ec290c7b355398492f6c36f8088"

  strings:
    $s1 = ":{create this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}