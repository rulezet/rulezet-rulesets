rule Virus_Infector_Generic_Dacic_F7D02F69_A_4FE5953A_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Generic.Dacic.F7D02F69.A.4FE5953A_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9792f0528d7b59372a88a7aaca4438f995895b1c1e29949fda505bec5ebad3f3"

  strings:
    $s1 = ":Description rdf:about=\"\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:photo" ascii
    $s2 = "MP Core 5.6-c142 79.160924, 2017/07/13-01:06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <" ascii
    $s3 = ":stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmp:CreatorTool=\"Adobe Pho" fullword ascii
    $s4 = "MP Core 5.6-c142 79.160924, 2017/07/13-01:06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <" ascii
    $s5 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}