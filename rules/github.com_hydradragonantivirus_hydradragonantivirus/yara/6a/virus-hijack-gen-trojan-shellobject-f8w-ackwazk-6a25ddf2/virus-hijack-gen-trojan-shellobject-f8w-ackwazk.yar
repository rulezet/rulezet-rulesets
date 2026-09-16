rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aCkwazk {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCkwazk.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33d64cda5b1777da19c7231565ea206e08c188eb59e575f8d4400777cbf55048"

  strings:
    $s1 = "Lby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}