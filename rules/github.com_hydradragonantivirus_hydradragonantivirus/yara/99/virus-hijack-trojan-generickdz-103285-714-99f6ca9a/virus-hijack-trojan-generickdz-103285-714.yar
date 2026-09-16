rule Virus_Hijack_Trojan_GenericKDZ_103285_714 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_714.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e033d54e26a0f518bc7518e4bf0cbed50391964f168ad961bca6d080a732224a"

  strings:
    $s1 = "@University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}