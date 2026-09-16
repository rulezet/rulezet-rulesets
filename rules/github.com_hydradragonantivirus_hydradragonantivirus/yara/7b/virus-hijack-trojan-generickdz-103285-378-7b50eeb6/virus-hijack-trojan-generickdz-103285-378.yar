rule Virus_Hijack_Trojan_GenericKDZ_103285_378 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_378.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e17374a3be5345b08f2e9e520cce07cf654c2b6520515613a3919b7936dbbc7"

  strings:
    $s1 = "J}SaIp" fullword ascii
    $s2 = "#\"SaIp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}