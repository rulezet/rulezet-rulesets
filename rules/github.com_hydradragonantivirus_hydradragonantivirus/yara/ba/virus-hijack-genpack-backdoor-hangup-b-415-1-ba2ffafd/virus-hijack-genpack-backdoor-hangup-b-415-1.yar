rule Virus_Hijack_GenPack_Backdoor_Hangup_B_415_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_415_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d0f787f14e3e50c27c6829d0225e33f36098490ff79135e1fed3e4120e5d3db"

  strings:
    $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
    $s2 = ".IEC 61966-2.1 Defaul= RGB colour space - sRGB" fullword ascii
    $s3 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999m02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmp=" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}