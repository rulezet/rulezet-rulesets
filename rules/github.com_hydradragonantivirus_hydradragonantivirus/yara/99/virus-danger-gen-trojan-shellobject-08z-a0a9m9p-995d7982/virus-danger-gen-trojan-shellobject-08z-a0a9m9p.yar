rule Virus_Danger_Gen_Trojan_ShellObject_08Z_a0a9m9p {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.08Z@a0a9m9p.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6665e6354976c17d3af038e5fff70eb6079c2a72d008e4a3d343a5f478f19762"

  strings:
    $s1 = "|Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}