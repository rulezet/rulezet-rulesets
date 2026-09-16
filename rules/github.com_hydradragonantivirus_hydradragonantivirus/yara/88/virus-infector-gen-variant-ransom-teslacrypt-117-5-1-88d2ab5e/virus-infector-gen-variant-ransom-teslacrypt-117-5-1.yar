rule Virus_Infector_Gen_Variant_Ransom_TeslaCrypt_117_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Gen.Variant.Ransom.TeslaCrypt.117_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e24f1eb7ad61e35d191539bed7f4606abe2955eac6174c00a41c2d92f6cbf86"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s2 = ",xeference Viewing Condition in IEC61966-2.1" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}