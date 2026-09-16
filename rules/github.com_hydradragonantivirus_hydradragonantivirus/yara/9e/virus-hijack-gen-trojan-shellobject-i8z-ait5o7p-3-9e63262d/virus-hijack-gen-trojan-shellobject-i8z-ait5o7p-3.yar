rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_ait5o7p_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@ait5o7p_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e040cba2d5881fe73b3a41a52f23aea2b9875f30fbb871d6e5f7cda3fc301b91"

  strings:
    $s1 = "Z4?%jEeP<-" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}