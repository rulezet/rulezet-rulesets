rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_490 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_490.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bd65d936dbea7b0ca5eddc6ce9190213ed36a8c275ba6817a5a46b22ee71bba"

  strings:
    $s1 = "@/Microsoft Ireland Operations Limited makes the l" fullword ascii
    $s2 = "and selling your products. Depending upon the type of industry`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}