rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_273 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_273.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83ade27b175a3d517ede858ca36abc8753b0d0ef32da1339c81ae46039648426"

  strings:
    $s1 = "iMicrosoft Ireland Operations Limited makes the l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}