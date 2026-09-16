rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_533_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_533_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1bdc2de6e9624f812cf049ac51fa6d6df6309d24c393ee00aeeda5678e267e8"

  strings:
    $s1 = "7JOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}