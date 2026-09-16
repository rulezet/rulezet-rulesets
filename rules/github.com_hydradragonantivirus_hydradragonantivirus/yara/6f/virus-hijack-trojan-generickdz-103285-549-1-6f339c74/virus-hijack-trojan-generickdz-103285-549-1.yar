rule Virus_Hijack_Trojan_GenericKDZ_103285_549_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_549_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59178119f54307298d6a5d1b33101aa3abcb46af78f5e217aea173e9424196bc"

  strings:
    $s1 = "Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:actiOn=\"converted\" stEvt:parameters=\"from image/png to image/jpeg\"/> <rdf:li " ascii
    $s2 = "4b651f934\" stRef:documentID=\"adobe:docid:photoshop:ee396c7e-5800-2842-91eb-924792347dc3\" stRef:originalDocumentID=\"xmp.did:9" ascii
    $s3 = "ndows)\" stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d77401-7124-ed42-8b71" ascii
    $s4 = "id:d5974899-ca88-7f42-9516-8e7635808df3\" stEvt:when=\"2019-01-07T19:44:27+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018" ascii
    $s5 = "eb3-7085-4449-8680-030e5a0890d3\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>                                                  " ascii
    $s6 = "Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:actiOn=\"converted\" stEvt:parameters=\"from image/png to image/jpeg\"/> <rdf:li " ascii
    $s7 = "ction=\"derived\" stEvt:parameters=\"converted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=" ascii
    $s8 = "gent=\"Adobe Photoshop CC 2018 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}