rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aCkwazk_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aCkwazk_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a7967030431b0a4a7ed3cccbc2f22ec2a645bb087eeec15dd0a659f5f51257c"

  strings:
    $s1 = "?by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}