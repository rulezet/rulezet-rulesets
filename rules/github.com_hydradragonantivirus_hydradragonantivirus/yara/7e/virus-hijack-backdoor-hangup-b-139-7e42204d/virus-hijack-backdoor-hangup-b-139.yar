rule Virus_Hijack_Backdoor_Hangup_B_139 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_139.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "925916ae305017ff9179c24aa6dae9c5dde10259757e35af2fa2a2fd9629d933"

  strings:
    $s1 = "tuw{coSt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}