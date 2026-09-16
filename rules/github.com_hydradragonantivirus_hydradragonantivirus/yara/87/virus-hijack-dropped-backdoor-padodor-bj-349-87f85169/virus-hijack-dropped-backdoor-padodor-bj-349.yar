rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_349 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_349.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "480387c043b3eb6e1155ef2ffab43dbd8611fa322f5ac070844768027e2c7431"

  strings:
    $s1 = "Q`MAUN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}