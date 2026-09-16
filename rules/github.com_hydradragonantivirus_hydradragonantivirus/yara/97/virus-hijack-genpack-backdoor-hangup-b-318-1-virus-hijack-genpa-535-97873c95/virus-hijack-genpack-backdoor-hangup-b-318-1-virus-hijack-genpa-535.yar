import "pe"
rule _Virus_Hijack_GenPack_Backdoor_Hangup_B_318_1_Virus_Hijack_GenPa_535 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_GenPack.Backdoor.Hangup.B_318_1.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_434_1.vir, Virus.Hijack_GenPack.Trojan.GenericKDZ.103285_12_1.vir, Virus.Hijack_Trojan.Agent.DQQO_168_1.vir, Virus.Hijack_Trojan.Agent.DQQO_351_1.vir, Virus.Hijack_Trojan.Agent.DQQO_55_1.vir, Virus.Hijack_Trojan.GenericKD.71558468_1_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_128_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_160_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_305_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_409_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_417_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_45_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_755_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_815_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b8ab298bcb3fabfbdded5947d011477afb0bba5666ce8ea7503cdeeabbb7392"
    hash2       = "0c4cd6c30d0b8bcb6f6921a1c7f74fb3703f23ddf131862a8c06b32e76b2fe1f"
    hash3       = "f7b52b17aed67d3ffdbded69fc6ff4c13f04925af606fbf8dce02dc220cae00b"
    hash4       = "413fe40858c9f58d26c572118ab8cd56e1db643f2ae5790ddfcfe6d29251b6ae"
    hash5       = "3c7c795ea9dd7204bb800c57906a48b670c9d0ce401515f356f73f5bc49b9381"
    hash6       = "a9f119f8e9861519e74ac8b711ac3b9b81485333ae5baf74ef06f87fc2bb191e"
    hash7       = "c419b962c352354b263933926c05a64057d4db27e702c7e38856028ff604ba9f"
    hash8       = "7af1b2f4ccad750b02be11ada70ed347b4ce14b9df5c71de9634dc378bd4ca43"
    hash9       = "a4f698a46598580caa36634f4d3e091e98d36d0c469314b874f637288b5eae17"
    hash10      = "88370151059902573f652a8c23dab3e9d89fee39346cc17ede0a63ff75afc62a"
    hash11      = "53f11eb0463561421a4b0ff4ca5fcb528f36315c76550ae852c65d237e65e29a"
    hash12      = "b9c00d86455dadda59d1941247aeeef439c980e5e685eb9ecb20e4b0ded04386"
    hash13      = "f7eec2a66506feb4fb718bb60c096d84ae01e6a1ee5291c40130df2cfb28ea2a"
    hash14      = "df724ce9b2f5decfd57ee0eb1dabe1756dce9f17958551dbbb4aa2ef4174ea87"
    hash15      = "c1fb79c8ceefa243e69750b6d8d21f9fe0a84adcb57f26d231949d66d3458404"

  strings:
    $s1 = "2-91eb-924792347dc3\" stRef:originalDocumentID=\"xmp.did:94317eb3-7085-4449-8680-030e5a0890d3\"/> </rdf:Description> </rdf:RDF> " ascii
    $s2 = "4:27+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> <xmpMM:" ascii
    $s3 = "jpeg\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:d5974899-ca88-7f32-9516-8e7635808df3\" stEvt:when=\"2V19-01-0" ascii
    $s4 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s5 = "edFrom stRef:instanceID=\"xmp.iid:d9d77401-7124-ed42-8b71-4014b651f934\" stRef:documentID=\"adobe:docid:photoshop:ee396c7e-5800-" ascii
    $s6 = "png to image/jpeg\"/> <rdf:li stEvt:action=\"derived\" stEvt:parameters=\"converted from image/png to image" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "7fbc9b04c929af491a168a8a4a05921f" and (all of them)
    ) or (all of them)
}