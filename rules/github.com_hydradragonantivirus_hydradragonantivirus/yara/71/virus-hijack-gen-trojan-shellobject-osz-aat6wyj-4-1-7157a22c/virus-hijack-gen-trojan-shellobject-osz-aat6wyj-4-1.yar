rule Virus_Hijack_Gen_Trojan_ShellObject_oSZ_aaT6Wyj_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.oSZ@aaT6Wyj_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f297f5840fd3fd28332b37c2aa15b313e7166ed0ead0adab8ef082a3782b43b"

  strings:
    $s1 = "Shell Infrastructure Host" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}