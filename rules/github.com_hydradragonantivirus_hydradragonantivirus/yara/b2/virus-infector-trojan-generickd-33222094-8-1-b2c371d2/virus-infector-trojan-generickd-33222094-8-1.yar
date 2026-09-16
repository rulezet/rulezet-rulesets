rule Virus_Infector_Trojan_GenericKD_33222094_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Trojan.GenericKD.33222094_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99bfc4d7fbafb5d2ff023392c9398fb7e0931cb837d7e7284d70a7d52c0c100a"

  strings:
    $s1 = "id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924# 2017/07/13-" ascii
    $s2 = ":39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmp=\"h" ascii
    $s3 = "id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924# 2017/07/13-" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}