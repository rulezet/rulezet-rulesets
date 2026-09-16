rule Virus_Hijack_Trojan_GenericKDZ_103285_633_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_633_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "554a67afb6b5d2e145d698231e4166e92164eed0fe049cc40504bba5ba1b4006"

  strings:
    $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}