rule Virus_Hijack_Trojan_GenericKDZ_105924_395_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_395_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e6a37b1d4f6dc211fc4291a856e2cddb7ed40d1de4f1cfccd5e479afce377b7"

  strings:
    $s1 = ";e:KNub" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}