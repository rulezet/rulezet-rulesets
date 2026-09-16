rule Virus_Hijack_Gen_Trojan_ShellObject_gyZ_aSgChKg_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyZ@aSgChKg_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8be9f97b026cb01d36f0521bc4d010e3b33ef1455d02f1a2e157df216b0f6be3"

  strings:
    $s1 = "&ruEN'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}