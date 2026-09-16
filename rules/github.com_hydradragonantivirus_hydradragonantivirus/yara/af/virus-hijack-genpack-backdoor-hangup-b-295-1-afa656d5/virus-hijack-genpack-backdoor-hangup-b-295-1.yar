rule Virus_Hijack_GenPack_Backdoor_Hangup_B_295_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_295_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7322ec0774bb6390eab4f49dee85ca89eb0cc3af6481091030f81b7fdb5d597"

  strings:
    $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
    $s2 = ".IEC 61966-2.1 Defaul= RGB colour space - sRGB" fullword ascii
    $s3 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999m02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmp=" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}