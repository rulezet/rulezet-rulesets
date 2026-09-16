rule Virus_Hijack_Trojan_GenericKDZ_105924_615_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_615_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e14faaacfc106ae69c950afea544d7ddee27c6a310e76a602ef98193f7fe6c1"

  strings:
    $s1 = "K\"itEM" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}