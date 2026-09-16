rule Virus_Hijack_Gen_Trojan_ShellObject_g4Y_a8fTg3h_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4Y@a8fTg3h_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff65e85fc636060761af75cc8b13c8b91b5c39ba810a32573f39032462f457c1"

  strings:
    $s1 = "maRE(E" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}