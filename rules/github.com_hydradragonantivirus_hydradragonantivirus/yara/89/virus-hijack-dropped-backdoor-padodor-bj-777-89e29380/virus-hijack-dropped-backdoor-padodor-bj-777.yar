rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_777 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_777.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5aa44c4943f22bf872cd0ca4eb4c7e00aee0c638f7ace290c52804dd4b55503d"

  strings:
    $s1 = "z?iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}