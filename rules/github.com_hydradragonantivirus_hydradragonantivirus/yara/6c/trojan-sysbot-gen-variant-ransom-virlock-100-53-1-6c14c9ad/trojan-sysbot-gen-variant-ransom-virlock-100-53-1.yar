rule Trojan_Sysbot_Gen_Variant_Ransom_VirLock_100_53_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Gen.Variant.Ransom.VirLock.100_53_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "813cc911aff2f69181ccb99952d8698bf15cd97d46c35b2c1e1c1834e7865539"

  strings:
    $s1 = "Task Scheduler.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}