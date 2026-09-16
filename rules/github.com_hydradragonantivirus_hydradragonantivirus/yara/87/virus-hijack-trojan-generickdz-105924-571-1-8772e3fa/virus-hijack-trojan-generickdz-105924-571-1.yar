rule Virus_Hijack_Trojan_GenericKDZ_105924_571_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_571_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "011eb643d9e814f4978866a161c42aad8af6fcfb5e6763be71b9b910fff45431"

  strings:
    $s1 = "A[{roKy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}