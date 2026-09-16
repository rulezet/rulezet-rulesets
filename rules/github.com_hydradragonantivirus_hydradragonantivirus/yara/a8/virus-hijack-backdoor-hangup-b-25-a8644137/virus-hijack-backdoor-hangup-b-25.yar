rule Virus_Hijack_Backdoor_Hangup_B_25 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_25.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b32f384a0c42939b7dfe4443effc8258b42f03fca722cafb2c985dc505e09b9d"

  strings:
    $s1 = "KA. Agreement Definitions" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}