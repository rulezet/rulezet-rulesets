rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_500 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_500.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3039c25025c5bd84a265a5f455a4f3b32067b056d83af4a25e329265dde2cd89"

  strings:
    $s1 = ".>and services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}