rule Virus_Hijack_Trojan_GenericKDZ_74550_232_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_232_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2aff76be6f4bb8d9c0854b574d0b8ef6b502df7cdf1a6d7cef750f7ff4fa66df"

  strings:
    $s1 = "quod,'" fullword ascii
    $s2 = "PIse:P" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}