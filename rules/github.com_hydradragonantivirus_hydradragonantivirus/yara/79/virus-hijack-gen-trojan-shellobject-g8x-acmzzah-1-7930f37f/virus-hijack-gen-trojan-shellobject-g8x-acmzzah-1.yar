rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aCMzZah_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aCMzZah_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0b270e796985d9c933b29569e9ef7780f1747cb4c2d56f292695e4ce06d0e49"

  strings:
    $s1 = ">orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}