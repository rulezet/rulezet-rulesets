rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_359 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_359.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bec84ad315adb75337153c46e81ea17913ed11143f3015670ba471909c61a12"

  strings:
    $s1 = "yand services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}