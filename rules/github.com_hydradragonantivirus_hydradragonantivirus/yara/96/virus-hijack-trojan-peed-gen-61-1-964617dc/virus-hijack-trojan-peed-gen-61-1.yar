rule Virus_Hijack_Trojan_Peed_Gen_61_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_61_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4054c4832e727ceb271eaf070de4b4b29aa770aeb57e82dc4762fd077859640e"

  strings:
    $s1 = "paHO}\"^" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}