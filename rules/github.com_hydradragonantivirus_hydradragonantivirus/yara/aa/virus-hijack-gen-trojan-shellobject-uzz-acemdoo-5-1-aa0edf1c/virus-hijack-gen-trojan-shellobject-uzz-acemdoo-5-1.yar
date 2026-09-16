rule Virus_Hijack_Gen_Trojan_ShellObject_UzZ_aCEmdoo_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.UzZ@aCEmdoo_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bce04a221be5ac5a01d185569e74d0c0909eb3c292b033f13a7fa42dcd2732a"

  strings:
    $s1 = "p.iid:94317eb3-7085-4449-8680-030e5a0890d3\" stEvt:when=\"2018-12-02T15:50:06+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2" ascii
    $s2 = "ourceRef#\" xmp:CreatorTool=\"Adobe Pho" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}