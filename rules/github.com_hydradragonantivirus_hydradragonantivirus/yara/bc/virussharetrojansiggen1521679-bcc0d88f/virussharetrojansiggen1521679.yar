rule VirusShareTrojanSiggen1521679 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1521679.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b2e7e65d91e879ea3a3409ff1bea5b7d23586ca68cd946fab58add75e88df9a"

  strings:
    $s1 = "London Jamocha Community CIC0" fullword ascii
    $s2 = "London Jamocha Community CIC1%0#" fullword ascii
    $s3 = "KERN`L32.dql" fullword ascii
    $s4 = "This prosg<am:c8n" fullword ascii
    $s5 = "juDO D" fullword ascii
    $s6 = "aMah``" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}