rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aCMzZah_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aCMzZah_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eae38c2ab9bac4d181d4f23da1ff61804062ab071864bac29db859316988d9e7"

  strings:
    $s1 = "'orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}