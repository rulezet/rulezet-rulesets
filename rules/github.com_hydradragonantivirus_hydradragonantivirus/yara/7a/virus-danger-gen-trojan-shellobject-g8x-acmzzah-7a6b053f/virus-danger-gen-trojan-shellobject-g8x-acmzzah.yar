rule Virus_Danger_Gen_Trojan_ShellObject_g8X_aCMzZah {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.g8X@aCMzZah.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02197b893d152421a93acc8b9b95bdca6e3cc6c41d6a2e62c9572641b6aea2d8"

  strings:
    $s1 = "^orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}