import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_w8Z_aqA82Sk_14_1_Virus_Hija_546 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.w8Z@aqA82Sk_14_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.wSZ@a024O7m_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.yyZ@aO@sVhl_20_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "931dcad872ae31228b134671cf740ded14848041873b9c086c7de2567c3d7ffa"
    hash2       = "d5f937c86c39bbfbbbf8c87f15cb4660f53b0570eb9eb854fed3d21178e32e72"
    hash3       = "f4299c300f87bb0a2b3341dc12cf3c5d5c504f27fabaabefcf4b3d89420f6f98"

  strings:
    $s1 = "08:00\" stEvt:softw+reAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"saved\" stEvt:ins" ascii
    $s2 = "reAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/>" fullword ascii
    $s3 = "</rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d77401-7124-ed42-8b71-4014b651f934\" stRef:documentI" ascii
    $s4 = "/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:bda3dc4b-caee-fd46-b85f-119c665623ef\" stEvt:when=\"2018-12-02T16:0" ascii
    $s5 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\"(stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "08a193ead28562e266d459a7d6f9c41a" and (all of them)
    ) or (all of them)
}