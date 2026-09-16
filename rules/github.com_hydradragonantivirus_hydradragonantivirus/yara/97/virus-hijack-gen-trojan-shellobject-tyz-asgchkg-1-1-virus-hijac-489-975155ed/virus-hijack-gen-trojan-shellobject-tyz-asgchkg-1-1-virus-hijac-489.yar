import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_tyZ_aSgChKg_1_1_Virus_Hijac_489 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.tyZ@aSgChKg_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.wCZ@aSAbsLg_6_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.WyZ@aCEmdoo_26_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.WyZ@aCEmdoo_30_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.WyZ@aCEmdoo_31_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.y8W@aKXYEud_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.y8W@aKXYEud_4.vir, Virus.Hijack_Gen.Trojan.ShellObject.yCZ@aSAbsLg_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.zuZ@a8I4DBe_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f822315c715d366ab794a416118a8c434ec4442b5e6ec34d64ff9c027323d984"
    hash2       = "053887de43adba1d4e01c82dd7ddc4e451955ec64fd0c6528f567185913f6d17"
    hash3       = "5bdd6f72fde6fe304fba78de1796a2205c9ce0ceba4f0b1656680b9216e8c5f4"
    hash4       = "04e30c14dbbb42a2f190169227de69b39aaae9c1f03a69309d01ad0480ba37f0"
    hash5       = "735f4f6e9032f69e1dff6c856c94023d3ee3c29848c0f40e9369f2938bd06f01"
    hash6       = "1ee47d27922116bbd88e606e5e33e498263168b5ace1b45b006c6d558f0651dc"
    hash7       = "9ac3d55892893152954dcd9c5c3177ee88d119c6c9fe10e3b9dc26f09ec1eb50"
    hash8       = "6c3969751d017da0a6732e8659fba393e53539c97c6e30aec47cde9511e7ac25"
    hash9       = "710b1d8e1548573e1848901d2d7121fb10d6db9764d4f2c5bdfaac5656018689"

  strings:
    $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii
    $s2 = "reAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:" fullword ascii
    $s3 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s4 = "94317eb3-7085-4449-8680-030e5a0890d3\" stEvt:when=\"2018-12-02T15:50:06+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (W" ascii
    $s5 = "nstanceID=\"xmp.iid:d9d77401-7124-ed42-8b71-4014b651f934\" stRef:documentID=\"adobe:docid:photoshop:ee396c7e-5800-2842-91eb-9247" ascii
    $s6 = "47dc3\" stRef:originalDocumentID=\"xmp.did:94317eb3-7085-4449-8680-030e5a0890d3\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>  " ascii
    $s7 = "nstanceID=\"xmp.iid:d9d77401-7124-ed42-8b71-4014b651f934\" stRef:documentID=\"adobe:docid:photoshop:ee396c7e-5800-2842-91eb-9247" ascii
    $s8 = "!This prUgram cannot be run in DOS mode." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "c3f2313f7ef4760b63404b0742d0bbf8" and (all of them)
    ) or (all of them)
}