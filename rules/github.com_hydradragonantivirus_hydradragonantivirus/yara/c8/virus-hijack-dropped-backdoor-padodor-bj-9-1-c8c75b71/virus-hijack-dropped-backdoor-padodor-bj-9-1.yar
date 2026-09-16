rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "344ba6264da5e63ecd4828ce234580938a9fc25878390287e644a14502dc1e71"

  strings:
    $s1 = "mdd4g<:hill<oDBpqttDwLJxy||L" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}