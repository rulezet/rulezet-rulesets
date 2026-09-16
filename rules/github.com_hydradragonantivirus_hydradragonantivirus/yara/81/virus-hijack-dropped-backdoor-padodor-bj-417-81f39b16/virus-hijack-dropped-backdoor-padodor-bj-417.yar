rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_417 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_417.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a6280dd6cc5ec1375c982ee69e6491943b53d2a98ecb3f66449ccb10e59b943"

  strings:
    $s1 = "kIf you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}