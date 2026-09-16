rule Virus_Hijack_Trojan_Agent_DQQO_435_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_435_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffa7c3780d8c07fb6c458bf343fda03578b533edc4bdded19167aed9aa68b364"

  strings:
    $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
    $s2 = ".IEC 61966-2.1 Defaul= RGB colour space - sRGB" fullword ascii
    $s3 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999m02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmp=" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}