rule Virus_Hijack_Gen_Trojan_ShellObject_oSZ_aaT6Wyj_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.oSZ@aaT6Wyj_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f2bb2bf64656f3bd4d2fbd3e98fbb462cbbcdf923af46b6a59eac2626ab462b"

  strings:
    $s1 = "?whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}