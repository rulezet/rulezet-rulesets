import "pe"
rule _Virus_Hijack_Trojan_Agent_DQQO_217_1_Virus_Hijack_Trojan_Generi_556 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.Agent.DQQO_217_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_456_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86428bc0513b9a8a805748be554612dbc8e4af2977ac0f8bda5ebd0787108df1"
    hash2       = "8d472d497d9a9ae740939416d17a4a463b5cad25b6c7cef659028834ee580979"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s2 = "saved\" stEvt:instanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" stEvt:when=\"2019-01-07T19:44:27+08:00\" stEvt:softwar" ascii
    $s3 = "ginalDocumentID=\"xmp.did:94317eb3-7085-4449-8680-030e5a0890d3\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>                   " ascii
    $s4 = "id:d9d77401-7124-ed42-8b71-4014b651f934\" stRef:documentID=\"adobe:docid:photoshop:ee396c7e-5800-2842-91eb-924792347dc3\" stRef:" ascii
    $s5 = "t=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "4aeb6721b008739916fb7a9bdda2ac2e" and (all of them)
    ) or (all of them)
}