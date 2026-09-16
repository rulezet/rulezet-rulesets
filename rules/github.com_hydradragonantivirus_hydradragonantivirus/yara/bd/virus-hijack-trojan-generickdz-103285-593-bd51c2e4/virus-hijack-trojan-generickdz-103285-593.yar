rule Virus_Hijack_Trojan_GenericKDZ_103285_593 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_593.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4dd0711b308c540d246ae0a09abc25632a026c32e195986d111bde583e299c1c"

  strings:
    $s1 = "z{WinY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}