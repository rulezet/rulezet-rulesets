rule Virus_Hijack_Trojan_GenericKDZ_105924_420_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_420_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "daa08ccbdf822b6e9137e7fb3845eabfb5cb18ffd6ad01322212b275cde397e8"

  strings:
    $s1 = "gONg#gw" fullword ascii
    $s2 = "scob#\"" fullword ascii
    $s3 = "8)GhEE#}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}