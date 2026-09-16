rule Virus_Hijack_Trojan_GenericKDZ_103285_381 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_381.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09597fccb088b01f37c81994643cb97f6ed973c2437b448626694b9a13f69c68"

  strings:
    $s1 = "OWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii
    $s2 = "62?tING" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}