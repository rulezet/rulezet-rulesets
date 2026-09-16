rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "621d6b3ec81ee8d0aeedfcfa11030efb0ee49ee3c5674dcf3e852baa3400396a"

  strings:
    $s1 = "Z8or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}