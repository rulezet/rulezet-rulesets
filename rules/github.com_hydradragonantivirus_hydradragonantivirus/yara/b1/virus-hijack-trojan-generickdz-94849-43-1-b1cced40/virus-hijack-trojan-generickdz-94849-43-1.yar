rule Virus_Hijack_Trojan_GenericKDZ_94849_43_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_43_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44f8f18590c536125fc5792aabf13d80729c374c6a46d30efadf179f2da1c102"

  strings:
    $s1 = "rhAmN%E" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}