rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd751d1d099f1202fa4dac1745492011ea4846e9345d2f443034035dd16e4599"

  strings:
    $s1 = "kor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}