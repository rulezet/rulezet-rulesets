rule Virus_Hijack_Trojan_GenericKDZ_103285_540_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_540_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a7a4255577bbdff9cdb10a9facdec3a2e142c6929039dc5cab08c540950ebb5"

  strings:
    $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
    $s2 = "06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}