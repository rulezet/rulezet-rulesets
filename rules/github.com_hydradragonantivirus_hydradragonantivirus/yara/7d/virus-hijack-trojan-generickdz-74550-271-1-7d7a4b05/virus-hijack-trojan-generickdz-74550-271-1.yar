rule Virus_Hijack_Trojan_GenericKDZ_74550_271_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_271_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1a106a5a456e4d132f9a8cff36a112a9d14a96ee6a8e8f3bbd049df92cad01a"

  strings:
    $s1 = "5%}gest:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}