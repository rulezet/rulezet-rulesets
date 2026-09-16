rule Virus_Hijack_Gen_Trojan_ShellObject_xyZ_aSgChKg_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.xyZ@aSgChKg_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e114f3b8e7ab9dbd1afce5d86c94e45201bc6b3fc5fe386dcd15482fec2d256"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s2 = "rdf:Description> </rdf:RDF> </x:xmpmeta>                                                                                        " ascii
    $s3 = "rdf:Description> </rdf:RDF> </x:xmpmeta>                                                                                        " ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}