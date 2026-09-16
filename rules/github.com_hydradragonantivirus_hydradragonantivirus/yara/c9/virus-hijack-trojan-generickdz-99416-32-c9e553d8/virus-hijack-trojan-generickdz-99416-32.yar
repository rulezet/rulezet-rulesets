rule Virus_Hijack_Trojan_GenericKDZ_99416_32 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_32.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e6753878b0ba593b4a2f7ed46a9c651b4852f3972a7013aa19472f46049d28d"

  strings:
    $s1 = "aUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}