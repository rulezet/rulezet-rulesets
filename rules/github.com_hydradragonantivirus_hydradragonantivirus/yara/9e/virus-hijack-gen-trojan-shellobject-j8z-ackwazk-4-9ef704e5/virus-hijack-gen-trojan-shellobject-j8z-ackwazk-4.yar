rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_aCkwazk_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@aCkwazk_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "220f59148f6a453cb9ef60756eb95e1d5ce831f20380ec7748e081da47cae511"

  strings:
    $s1 = "`by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}