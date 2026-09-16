rule Virus_Hijack_Trojan_GenericKDZ_103285_646_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_646_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63800f68134521812b60ff7a00755c0cc5f202f9c1da3ea312a3e106c2b6a057"

  strings:
    $s1 = ":02:59+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"saved\" st" ascii
    $s2 = "id:94317eb3-7085-4449-8680-030e5a0890d3\" stEvt:when=\"2018-12-02T15:50:06+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018" ascii
    $s3 = "id:94317eb3-7085-4449-8680-030e5a0890d3\" stEvt:when=\"2018-12-02T15:50:06+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018" ascii
    $s4 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}