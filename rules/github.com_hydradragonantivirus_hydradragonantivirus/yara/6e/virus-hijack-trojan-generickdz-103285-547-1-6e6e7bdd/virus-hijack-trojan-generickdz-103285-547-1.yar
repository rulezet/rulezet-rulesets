rule Virus_Hijack_Trojan_GenericKDZ_103285_547_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_547_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ccb7b71cee66dff4df5f5afd9e40111f5c14560e20f7bf3a45dbe268afae3db"

  strings:
    $s1 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6" ascii
    $s2 = "d=\"/\"/> <rdf:li stEvt:action=\"save" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}