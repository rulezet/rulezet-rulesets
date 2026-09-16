rule Virus_Hijack_Trojan_GenericKDZ_103285_859_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_859_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d66da2d8bd4023d742255b3eefb2a190f99f3ba96e53fec8a5865af251b0eb27"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s2 = "df:Description> </rdf:RDF> </x:xmpmeta>                                                                                         " ascii
    $s3 = "df:Description> </rdf:RDF> </x:xmpmeta>                                                                                         " ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}