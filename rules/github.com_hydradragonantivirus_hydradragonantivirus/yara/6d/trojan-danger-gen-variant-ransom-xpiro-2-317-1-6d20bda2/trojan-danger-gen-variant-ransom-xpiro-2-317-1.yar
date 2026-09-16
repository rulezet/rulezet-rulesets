rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_317_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_317_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1b95443218c7be24ca6d034befb0cfdcf4dbe46cad911350f873232b84f0695"

  strings:
    $s1 = "Peep$m" fullword ascii
    $s2 = "$Omer%o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}