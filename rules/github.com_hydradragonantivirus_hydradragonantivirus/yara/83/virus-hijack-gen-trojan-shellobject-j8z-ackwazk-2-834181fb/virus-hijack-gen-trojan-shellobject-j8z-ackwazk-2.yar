rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_aCkwazk_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@aCkwazk_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f48bedb624bee80c7b4e03159877b25cbf625230cd234c21a87381cac1212ea"

  strings:
    $s1 = "jby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}