rule Virus_Hijack_Trojan_GenericKDZ_105924_93_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_93_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a9f355aaf209a49e9c77b2f4a3f2cc72e76c8f8c64df086f2c158d999e1dc1d"

  strings:
    $s1 = "kIlp?*" fullword ascii
    $s2 = "fain#\\2" fullword ascii
    $s3 = "%BUMP*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}