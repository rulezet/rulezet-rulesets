rule Virus_Hijack_Trojan_GenericKDZ_105924_316_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_316_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1f25f0cc2db700e9eaa5ed97a550b85c343aadeb4fd31a8a61c65bb77abd71c"

  strings:
    $s1 = "U?#lIlt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}