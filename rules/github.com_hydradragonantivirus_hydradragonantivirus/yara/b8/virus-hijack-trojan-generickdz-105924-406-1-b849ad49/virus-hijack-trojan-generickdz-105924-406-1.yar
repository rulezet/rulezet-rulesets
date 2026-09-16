rule Virus_Hijack_Trojan_GenericKDZ_105924_406_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_406_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd0c7809d8cbf5cfcab2db52a33ca86803da3508f6f8608c19538d35a395818f"

  strings:
    $s1 = "l#ROub" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}