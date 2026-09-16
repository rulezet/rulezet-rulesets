rule Virus_Hijack_Trojan_GenericKDZ_98388_62_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_62_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fb82c9e9023ed333d34dcc6eaa690c06a61a1d26da471e6ebc3e202f1091bfc"

  strings:
    $s1 = "InkY$*wM" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}