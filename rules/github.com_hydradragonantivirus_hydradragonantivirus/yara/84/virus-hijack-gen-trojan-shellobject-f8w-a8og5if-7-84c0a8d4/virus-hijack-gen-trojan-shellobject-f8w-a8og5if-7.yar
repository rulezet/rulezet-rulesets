rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a8oG5if_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oG5if_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3013a140cdb3577e5b1d4cbc91d850ebbd8105c9c0ddbee7d26f922abbca2602"

  strings:
    $s1 = "<Nby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}