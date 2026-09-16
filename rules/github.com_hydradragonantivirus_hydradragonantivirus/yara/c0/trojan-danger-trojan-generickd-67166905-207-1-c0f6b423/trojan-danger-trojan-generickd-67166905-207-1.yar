rule Trojan_Danger_Trojan_GenericKD_67166905_207_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_207_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a821e5b6fc3434628801167dc762d95c18424d69a8c3ba974ff5e951f071ff00"

  strings:
    $s1 = "kUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}