rule Trojan_Autorun_Trojan_GenericKD_72517131_184_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_184_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18bf68ef6efe4a7daaa8dd78957dcf103bf6dc7d5b49a683c2724d35e0bdb7da"

  strings:
    $s1 = "argo{Z*Y5" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}