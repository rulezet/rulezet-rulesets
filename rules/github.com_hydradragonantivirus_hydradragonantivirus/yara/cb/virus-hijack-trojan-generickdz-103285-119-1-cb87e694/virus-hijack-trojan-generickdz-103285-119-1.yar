rule Virus_Hijack_Trojan_GenericKDZ_103285_119_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_119_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62c5253ac0476ff1164bacc13f7b0c2746bb41c11869f2d160a45582fa8c0a76"

  strings:
    $s1 = "\"converted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8" ascii
    $s2 = "808df3\" stEvt:when=\"2019-01-07T19:44:27+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/" ascii
    $s3 = ":Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d77401-7124-ed42-8b71-4014b#51f934\" stRef:documentID=\"a" ascii
    $s4 = "> </rdf:Description> </rdf:RDF> </x:xmpmeta>                                                                                    " ascii
    $s5 = "\"converted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}