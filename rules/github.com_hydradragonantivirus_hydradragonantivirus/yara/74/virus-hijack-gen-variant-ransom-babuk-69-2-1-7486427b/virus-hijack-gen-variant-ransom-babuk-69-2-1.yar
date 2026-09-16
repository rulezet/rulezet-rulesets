rule Virus_Hijack_Gen_Variant_Ransom_Babuk_69_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Ransom.Babuk.69_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae65272fa537437fbc8a6e30d6039b7a0771628f1d6639aa623f15176c5f4abc"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Wind#ws)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s2 = "wareAgent=\"Adobe Photoshop CC 2018 (Wind#ws)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s3 = "\"xmp.iid:d9d77401-7124-ed42-8b71-4014b651f934\" stRef:documentID=\"adobe:docid:photoshopSee396c7e-5800-2842-91eb-924792347dc3\"" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}