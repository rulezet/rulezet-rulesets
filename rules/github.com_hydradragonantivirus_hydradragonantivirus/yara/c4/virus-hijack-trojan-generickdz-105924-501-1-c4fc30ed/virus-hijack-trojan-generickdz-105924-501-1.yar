rule Virus_Hijack_Trojan_GenericKDZ_105924_501_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_501_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f46cba49215d8fa8df5999be27f639111c3d8fdb2b72b8902b6ecd7c107e5e42"

  strings:
    $s1 = "g LiRA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}