rule Virus_Hijack_Trojan_GenericKDZ_98113_353_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_353_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0055d1626c0b7e8ca87b68928a007adb8d2deff288d6a567da06765fb17aebf4"

  strings:
    $s1 = "U[JAMb" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}