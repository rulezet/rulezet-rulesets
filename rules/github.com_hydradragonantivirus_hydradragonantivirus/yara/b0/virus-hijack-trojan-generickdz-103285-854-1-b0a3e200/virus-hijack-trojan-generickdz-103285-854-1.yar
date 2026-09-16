rule Virus_Hijack_Trojan_GenericKDZ_103285_854_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_854_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "140048932a4a87a524572530d2a5a3f0d30e1193ef665b00e665bde7228e84d2"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s2 = "df:Description> </rdf:RDF> </x:xmpmeta>                                                                                         " ascii
    $s3 = "df:Description> </rdf:RDF> </x:xmpmeta>                                                                                         " ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}