rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aCMzZah_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aCMzZah_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb75c66afd3d0dd48a62a5dea6878c9b4ac760484510b66f9fd2d5f2c83d05a6"

  strings:
    $s1 = "eorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}