rule Virus_Hijack_Trojan_GenericKDZ_99416_43 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_43.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "145e6c06ad1cb7b7fb602ce846b6e310d4af08e52845afbe6a405466b2b9ab21"

  strings:
    $s1 = "(fUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}