rule Virus_Hijack_Gen_Trojan_ShellObject_g4Y_a8fTg3h_22_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4Y@a8fTg3h_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6bc65af691fc51f76dbfa492533298a44b340de1e0baf929152812d18b2e6f6"

  strings:
    $s1 = "()Pize" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}