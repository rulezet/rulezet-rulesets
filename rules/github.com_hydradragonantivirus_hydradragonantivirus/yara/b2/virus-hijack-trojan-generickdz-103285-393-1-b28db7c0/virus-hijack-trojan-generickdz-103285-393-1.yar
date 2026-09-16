rule Virus_Hijack_Trojan_GenericKDZ_103285_393_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_393_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2a79e9cbef9dd423d701dfeaf375435759788a4e8d5a428f7d933a9099ba092"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:pargmeters=\"frrm" ascii
    $s2 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:pargmeters=\"frrm" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}