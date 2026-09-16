rule Virus_Hijack_Gen_Trojan_ShellObject_RAZ_aCEmdoo_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.RAZ@aCEmdoo_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f910deafe132c88ec0111d7fbee4b569581936a027d1a96b561406d5ca4e3f8"

  strings:
    $s1 = " 2009 - 2023 www.sordum.org All Rights Reserved." fullword wide
    $s2 = "DNS Jumper v2.3" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}