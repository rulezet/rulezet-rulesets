rule Virus_Hijack_Backdoor_Hangup_B_68 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_68.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99bc43c2493c758f79b16957ac6ae0f7e650fdc45e960c85315efbcf5a96d579"

  strings:
    $s1 = "Pand hardware systems to the applications programs and (c) building extensions to applications programs. You shall not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}