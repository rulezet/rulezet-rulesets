rule Virus_Hijack_Trojan_GenericKDZ_74550_236_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_236_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9382022cf6ab659674f7692ca61bc8009b8c946594d36fe4ff419d79fe63d18e"

  strings:
    $s1 = "kF;lIsK" fullword ascii
    $s2 = ":(gAUT" fullword ascii
    $s3 = "a3&SaFT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}