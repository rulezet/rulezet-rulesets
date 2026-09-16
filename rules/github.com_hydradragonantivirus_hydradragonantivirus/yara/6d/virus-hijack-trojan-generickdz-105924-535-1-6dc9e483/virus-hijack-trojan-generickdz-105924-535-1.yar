rule Virus_Hijack_Trojan_GenericKDZ_105924_535_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_535_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c9c92302803939d6fc51e1f33a39f5ed11cdab839a765499b9aa6183967a10e"

  strings:
    $s1 = "9(nGaI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}