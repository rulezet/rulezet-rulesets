rule Virus_Hijack_Trojan_GenericKDZ_74550_206_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_206_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ddf2b620a642a243616e2a2d8a766c6deb5b07a8562f5950b39dd34adac4e19"

  strings:
    $s1 = "gHq;taNh" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}