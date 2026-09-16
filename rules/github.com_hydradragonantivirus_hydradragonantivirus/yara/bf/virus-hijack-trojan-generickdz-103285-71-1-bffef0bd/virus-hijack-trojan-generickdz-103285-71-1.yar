rule Virus_Hijack_Trojan_GenericKDZ_103285_71_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_71_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ae07fee995f9b390ed1020d7b33ca1981b04e94015ec5637582cf9e680e95d1"

  strings:
    $s1 = "gent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:actiOn=\"converted\" stEvt:parameters=\"from imag" ascii
    $s2 = "iid:d9d77401-7124-ed42-8b71-4014b651f934\" stRef:documentID=\"adobe:docid:photoshop:ee396c7e-5800-2842-91ej-924792347dc3\" stRef" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}