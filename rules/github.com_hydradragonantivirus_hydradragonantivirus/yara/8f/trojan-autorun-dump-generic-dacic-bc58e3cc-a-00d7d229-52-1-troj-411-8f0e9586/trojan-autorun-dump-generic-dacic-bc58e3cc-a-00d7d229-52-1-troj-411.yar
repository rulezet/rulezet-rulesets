import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_52_1_Troj_411 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_52_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_570_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_81_1.vir, Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_16_1.vir, Virus.Hijack_Backdoor.Hangup.B.vir, Virus.Hijack_Backdoor.Hangup.B_180.vir, Virus.Hijack_Backdoor.Hangup.B_219.vir, Virus.Hijack_Backdoor.Hangup.B_223.vir, Virus.Hijack_Backdoor.Hangup.B_253.vir, Virus.Hijack_Backdoor.Hangup.B_266.vir, Virus.Hijack_Backdoor.Hangup.B_72.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_143.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_160.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_170.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_264.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_299.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_435.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_442.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_90.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d3e5a216a28941d4e535b60e4414746894b43f107a216a007a2f2e45cb8f593"
    hash2       = "b5871ec6cd07dcdef8ffdff12a8dfd91fb781d6dbbd3bf306131a790e563115f"
    hash3       = "4b41f7372e0ac19218662190293365b2a5d1342396fb00c3040c1245956ced15"
    hash4       = "d557453103658dcd538740686706d5e488268323d68907cf2ffe35cd45763445"
    hash5       = "c23859540aefe03ca6f16181c8ab59b8e7f7d4559265e5e8123d17f418a5bd4b"
    hash6       = "6195e398216a29bd06137224df4c246da122e8f1b4fb43da808c573ac85aebde"
    hash7       = "7c2d03a35b4061d584a86f65120372944a651de937c9ccb649bff64f7285b74d"
    hash8       = "9d32a1ba7d1c71f7b2df00947c128cc177a56259baf78b39fe70bfe5cb3d2cb2"
    hash9       = "4ac606cccef7a9fe63392ff8a17a6bd7bc0430eb446aa5df9e20a42c2d29f825"
    hash10      = "6039b120d18b72dfa4ff9b300e9ac9d5de2587f0c68d2ada27a42e5038c2d2d4"
    hash11      = "56134108d7ab2521ef2b408db98eacc7e4bcfbdde054eff6071052bf2854f2d0"
    hash12      = "486aa2dd0b525a25969ae9aec2e55bf433a1eedc7b86762a8c6aa91ffbc43f0e"
    hash13      = "b64cd4819948eb024fa7ca570f8ccc2d3f55ba0b9bc26c15cc17e02b2a5c0a34"
    hash14      = "e802e0bd622e33a6a93404877efb18a8194ca4ea2ba0847d7cf331399fe148d6"
    hash15      = "94fbd59cc25cbd88e7b32fb19097c4c14af8685d1809a7071cfa08cb9aa6649c"
    hash16      = "562e201769b20545c66bb5b29a2b17534f8654e27ea0253495486902b84b33ae"
    hash17      = "8a81bd0e279121ede1b621a32c1b4abce6419883cd8fed07a8280d24bf5e68ad"
    hash18      = "e9740545a42c6d52653663f6f60cda24ed75ee449f1536fff95e6929170b4324"
    hash19      = "31256088c60bad63eab4c43701c29dd9720058ef1cb1d3162fc9bdb50f7f3b03"

  strings:
    $s1 = "ax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmlns:dc=\"http://purl.org/dc/elements/1.1/" ascii
    $s2 = "ax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmlns:dc=\"http://purl.org/dc/elements/1.1/" ascii
    $s3 = "xap/1.0/sType/ResourceEvent#\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmp:CreatorTool=\"Adobe Photoshop " ascii
    $s4 = "instanceID=\"xmp.iid:94317eb3-7085-4449-8680-030e5a0890d3\" stEvt:when=\"2018-12-02T15:50:06+08:00\" stEvt:softwareAgent=\"Adobe" ascii
    $s5 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s6 = "iginalDocumentID=\"xmp.did:94317eb3-7085-4449-8680-030e5a0890d3\"> <xmpMM:History> <rdf:Seq> <rdf:li stEvt:action=\"created\" st" ascii
    $s7 = "iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6-8f45-b6a0-9baf393cacbc\" xmpMM" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "95e6f8741083e0c7d9a63d45e2472360" and (all of them)
    ) or (all of them)
}