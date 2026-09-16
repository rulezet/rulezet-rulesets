rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_ayeDwnk_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@ayeDwnk_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb1c29d358e81fd3ecde57d1b1668d16b76ef006ca565f11c8ad649724342e86"

  strings:
    $s1 = "F`werf" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}