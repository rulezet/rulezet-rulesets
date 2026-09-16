rule Virus_Hijack_GenPack_Backdoor_Hangup_B_472 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_472.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd0e538ff76aa1b91f4306273fbc5ab7c519cc9a15ea21a9b14a2135e7eeac86"

  strings:
    $s1 = "tuw{coSt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}