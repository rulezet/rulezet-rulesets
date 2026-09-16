rule Virus_Hijack_Trojan_GenericKDZ_79663_103_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_103_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aed259248d052c268a3673f0798faa80b008449cacc46763d38ae898b3eaa7e9"

  strings:
    $s1 = "o+',SKEy" fullword ascii
    $s2 = "&SPuN%D" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}