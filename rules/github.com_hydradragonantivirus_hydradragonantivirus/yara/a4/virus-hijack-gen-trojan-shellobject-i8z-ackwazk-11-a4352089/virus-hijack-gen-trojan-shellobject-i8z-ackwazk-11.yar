rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aCkwazk_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aCkwazk_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66d71f74f58884b6afa7430661e3910a1754337452df25277708c8ad8b385a09"

  strings:
    $s1 = "Lby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}