rule Virus_Infector_Win32_Expiro_Gen_7_106_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_106_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8af3ed0b36b6b35dfdf92279f5ac1064f128ab658c22cceee31f8d0c499c806"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s2 = "twareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:inst" ascii
    $s3 = ":action=\"saved\" stEvt:instanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" stEvt:when=\"2019-01-07T19:44:27+08:00\" stE" ascii
    $s4 = "stRef:originalDocumentID=\"xmp.did:94317eb3-7085-4449-8680-030e5a0890d3\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>          " ascii
    $s5 = "ID=\"xmp.iid:d9d77401-7124-ed42-8b71-4014b651f934\" stRef:documentID=\"adobe:docid:photoshop:ee396c7e-5800-2842-91eb-924792347dc" ascii
    $s6 = "png to image/jpeg\"/> <rdf:li stEvt:action=\"derived\" stEvt:parameters=\"converted from image/png to image/jpeg\"/> <rdf:li stE" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}