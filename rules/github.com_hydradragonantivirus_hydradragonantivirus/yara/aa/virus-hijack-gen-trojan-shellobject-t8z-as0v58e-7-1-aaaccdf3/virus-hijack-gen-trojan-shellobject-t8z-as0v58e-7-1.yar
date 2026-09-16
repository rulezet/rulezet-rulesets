rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aS0V58e_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aS0V58e_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f955d00a40b3b681b5cdda1eaaf6c0287bce4d018fefb0dd86f0a225deb268a8"

  strings:
    $s1  = " <rdf:Description rdf:about=\"\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:" ascii
    $s2  = "obe XMP Core 5.6-c142 79.160924, 2017/07/13-01:06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#" ascii
    $s3  = "/photoshop/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#" ascii
    $s4  = "lns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmp:Creator" fullword ascii
    $s5  = "reAgent=\"Adobe Photoshop CC 2018 (W" fullword ascii
    $s6  = ":59+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"saved\" stEvt" ascii
    $s7  = "mpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d77401-7124-ed42-8b71-4014b651f934\" stRef:documentID=\"adobe:doci" ascii
    $s8  = "94317eb3-7085-4449-8680-030e5a0890d3\" stEvt:when=\"2018-12-02T15:50:06+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (W" ascii
    $s9  = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s10 = "obe XMP Core 5.6-c142 79.160924, 2017/07/13-01:06:39        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#" ascii
    $s11 = "mpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d77401-7124-ed42-8b71-4014b651f934\" stRef:documentID=\"adobe:doci" ascii
    $s12 = "ool=\"Adobe Photoshop CC 2018 (Windows)\" xmp:CreateDate=\"2018-12-02T15*50:06+08:00\" xmp:ModifyDate=\"2019-01-07T19:44:27+08:0" ascii
    $s13 = "ool=\"Adobe Photoshop CC 2018 (Windows)\" xmp:CreateDate=\"2018-12-02T15*50:06+08:00\" xmp:ModifyDate=\"2019-01-07T19:44:27+08:0" ascii
    $s14 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"A" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}