rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8823c2b379599e7540abd1fbd76ca7f48aea2280ca0002fb9e4df015fa9d2865"

  strings:
    $s1 = "3$TAcT" fullword ascii
    $s2 = "hASK<7" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}