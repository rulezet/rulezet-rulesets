rule Virus_Hijack_Trojan_GenericKDZ_105924_32_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_32_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96d77a35da8c973a56eb0212f8daa00535fffb27fdeb2415defa688f0fe35d4d"

  strings:
    $s1 = "7Nw+$haiK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}