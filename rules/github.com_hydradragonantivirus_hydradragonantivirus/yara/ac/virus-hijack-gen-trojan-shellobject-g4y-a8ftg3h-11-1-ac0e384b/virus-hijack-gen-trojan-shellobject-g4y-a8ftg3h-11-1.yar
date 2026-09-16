rule Virus_Hijack_Gen_Trojan_ShellObject_g4Y_a8fTg3h_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4Y@a8fTg3h_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ddfa7d2644e31d28f4c95460dc8d88ae16cb83ac41dd3118595274e91e71b67"

  strings:
    $s1 = "M;C,b@QUET" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}