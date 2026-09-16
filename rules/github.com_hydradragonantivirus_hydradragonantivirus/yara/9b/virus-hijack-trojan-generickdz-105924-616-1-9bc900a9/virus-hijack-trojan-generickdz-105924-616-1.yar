rule Virus_Hijack_Trojan_GenericKDZ_105924_616_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_616_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "888af770db48d7e62a8ef9614d5c25323ef4f9d13d4c77f325b3a8471b563fd1"

  strings:
    $s1 = "ZX(LURg" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}