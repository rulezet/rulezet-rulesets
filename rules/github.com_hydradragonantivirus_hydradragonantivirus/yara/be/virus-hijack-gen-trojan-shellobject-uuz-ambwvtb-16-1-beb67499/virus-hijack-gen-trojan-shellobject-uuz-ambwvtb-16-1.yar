rule Virus_Hijack_Gen_Trojan_ShellObject_uuZ_amBwvTb_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uuZ@amBwvTb_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6454bced0a1a17d15efdb3f0ea0e3304b049de8c754f2e8b41a0f0b2fcce155c"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s2 = "rdf:Description> </rdf:RDF> </x:xmpmeta>                                                                                        " ascii
    $s3 = "rdf:Description> </rdf:RDF> </x:xmpmeta>                                                                                        " ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}