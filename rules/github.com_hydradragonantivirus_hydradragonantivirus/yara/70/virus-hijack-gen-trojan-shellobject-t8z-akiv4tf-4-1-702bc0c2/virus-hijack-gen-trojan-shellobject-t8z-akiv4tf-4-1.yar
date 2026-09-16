rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aKiV4Tf_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aKiV4Tf_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1968ab7a27c5941bf79095a904c1f1ca65a4114f236c48d5bb15676bbe1d6690"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s2 = ":li stEvt:action=\"derived\" stEvt:parameters=\"converted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:" ascii
    $s3 = "p.did:94317eb3-7085-4449-8680-030e5a0890d3\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>                                       " ascii
    $s4 = "ceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" stEvt:when=\"2019-01-07T19:44:27+08:00\" stEvt:softwareAgent=\"Adobe Photo" ascii
    $s5 = "CC 2018 (Windows)\" stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d77401-712" ascii
    $s6 = "42-8b71-4014b651f934\" stRef:documentID=\"adobe:docid:photoshop:ee396c7e-5800-2842-91eb-924792347dc3\" stRef:originalDocumentID=" ascii
    $s7 = ":li stEvt:action=\"derived\" stEvt:parameters=\"converted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}