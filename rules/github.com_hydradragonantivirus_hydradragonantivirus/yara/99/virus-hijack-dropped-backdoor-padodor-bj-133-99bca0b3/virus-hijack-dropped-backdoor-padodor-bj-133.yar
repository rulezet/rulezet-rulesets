rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_133 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_133.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92da9ff1c676241cc9ed9db96c601070dd4f985d52e85c9c74a5e70889f76926"

  strings:
    $s1 = "kiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}