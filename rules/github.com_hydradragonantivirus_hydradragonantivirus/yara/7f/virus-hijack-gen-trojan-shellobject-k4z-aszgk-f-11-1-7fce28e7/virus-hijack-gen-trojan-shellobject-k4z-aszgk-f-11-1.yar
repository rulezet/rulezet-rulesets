rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "183fe60685793684667d24b70fc07dd85dbc44551cc61c7186b191ead7da0c20"

  strings:
    $s1 = "Version 2.1.1" fullword wide
    $s2 = "Copyright by Nego" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}