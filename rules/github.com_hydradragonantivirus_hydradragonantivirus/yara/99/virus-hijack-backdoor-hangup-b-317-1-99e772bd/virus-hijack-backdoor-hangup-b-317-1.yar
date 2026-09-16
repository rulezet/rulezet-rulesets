rule Virus_Hijack_Backdoor_Hangup_B_317_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_317_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c63faf486f2aee454d66d217be16137c54665039b3a655787f9fa507dd0849d"

  strings:
    $s1 = "acknowledge that you will create and activate an administrator account and password and that the" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}