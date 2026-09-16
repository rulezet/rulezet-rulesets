rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_762 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_762.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b1018bf4d17a04f7e58124de47fc61471fa60ed92951b35f859a76358d346a4"

  strings:
    $s1 = "EiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}