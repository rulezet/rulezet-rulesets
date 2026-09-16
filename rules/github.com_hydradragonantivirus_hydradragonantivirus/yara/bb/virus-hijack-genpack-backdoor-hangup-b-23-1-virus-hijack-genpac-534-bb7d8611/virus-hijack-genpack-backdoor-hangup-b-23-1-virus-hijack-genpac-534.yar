import "pe"
rule _Virus_Hijack_GenPack_Backdoor_Hangup_B_23_1_Virus_Hijack_GenPac_534 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_GenPack.Backdoor.Hangup.B_23_1.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_279_1.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_384_1.vir, Virus.Hijack_Trojan.Agent.DQQO_412_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "752d9b90c424e51bafb91459d8e55d859ef4b6ecee18294a07e105e77158a3a7"
    hash2       = "576a022ed24aa071b6268f33f83dbe1ca5a3dd2c23f20c2c40a64d53fac52ae8"
    hash3       = "090ea967a7a74ccedd37e5850756097573397c88ea2fb50dcef781c22da68240"
    hash4       = "a725aae86a9cf4b54a77091ffafa366c243d4851a3ca9c005bde39814e2b2533"

  strings:
    $s1 = "xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" stEvt:when=\"2019-01-07T19:44:27+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC" ascii
    $s2 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s3 = "Evt:action=\"derived\" stEvt:parameters=\"converted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:instan" ascii
    $s4 = "1-4014b651f934\" stRef:documentID=\"adobe:docid:photoshop:ee396c7e-5800-2842-91eb-924792347dc3\" stRef:originalDocumentID=\"xmp." ascii
    $s5 = "8 (Windows)\" stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d77401-7124-ed42" ascii
    $s6 = "94317eb3-7085-4449-8680-030e5a0890d3\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>                      " fullword ascii
    $s7 = "Evt:action=\"derived\" stEvt:parameters=\"converted from image/png to image/jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:instan" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "e336e6f1b2351c4ae4996e78181bf640" and (all of them)
    ) or (all of them)
}