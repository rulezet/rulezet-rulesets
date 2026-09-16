rule Virus_Hijack_Trojan_GenericKDZ_103285_46_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_46_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "569aa5d9fee0f20b903f15cdac4394a9bf4bc9ef89c5b7900aa1aadbc1060b9f"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)' stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from " ascii
    $s2 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}