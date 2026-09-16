rule Virus_Hijack_Trojan_GenericKDZ_103285_307_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_307_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0655d85a65d5b249289d7e198e1ac1c3ffc6902f11a7eca7472f9f899c20223b"

  strings:
    $s1 = "gent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:actiOn=\"converted\" stEvt:parameters=\"from imag" ascii
    $s2 = "Description> </rdf:RDF> </x:xmpmeta>                                                                                            " ascii
    $s3 = "Description> </rdf:RDF> </x:xmpmeta>                                                                                            " ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}