rule Virus_Hijack_Trojan_GenericKDZ_105924_336_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_336_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71626c83a6794d4ef802af6224e74d6e2a934b684ab9256b9b4a5b24737e087d"

  strings:
    $s1 = ";jOck?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}