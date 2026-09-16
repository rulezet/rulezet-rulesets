rule Virus_Danger_Gen_Trojan_ShellObject_g8W_au0WBJh {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.g8W@au0WBJh.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21a099cebcb7d4bd74d00d47d485b485e6164b4edec303963767118c8080ca1f"

  strings:
    $s1 = "Zorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}