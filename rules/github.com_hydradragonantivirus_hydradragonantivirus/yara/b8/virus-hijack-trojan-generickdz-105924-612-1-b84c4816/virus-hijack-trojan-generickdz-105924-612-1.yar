rule Virus_Hijack_Trojan_GenericKDZ_105924_612_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_612_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07da7c44a5d63d30e805cd7b16a3892ca3ef062d82ee5cefef70985320dca766"

  strings:
    $s1 = "dUSt{Y" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}