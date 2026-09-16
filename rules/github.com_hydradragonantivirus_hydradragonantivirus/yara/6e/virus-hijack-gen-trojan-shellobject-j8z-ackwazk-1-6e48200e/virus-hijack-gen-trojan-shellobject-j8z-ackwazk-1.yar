rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_aCkwazk_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@aCkwazk_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fb3f6f9fa5e01ca082cdd1e2ebb2b560d4f10b2ba1a891722c4efc0176369e7"

  strings:
    $s1 = "@by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}