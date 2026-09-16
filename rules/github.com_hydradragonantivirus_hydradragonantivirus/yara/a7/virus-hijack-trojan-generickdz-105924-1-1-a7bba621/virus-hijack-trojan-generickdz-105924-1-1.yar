rule Virus_Hijack_Trojan_GenericKDZ_105924_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04805b7d0f29556a1e4c4adac8acc3d4501a7ca66b440adb9e288f7ba515ad0f"

  strings:
    $s1 = "piCo}LUlH`p" fullword ascii
    $s2 = "dANg!*" fullword ascii
    $s3 = "{,mONe*&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}