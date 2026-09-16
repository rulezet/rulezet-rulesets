rule Virus_Hijack_Trojan_GenericKDZ_105924_326_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_326_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43f531f153f357c558d1f8ac7df9acca36c5f7b3925324f1956ba75bd7a7b481"

  strings:
    $s1 = "denE(J1" fullword ascii
    $s2 = "wuLl@C" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}