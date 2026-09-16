rule Virus_Hijack_Gen_Trojan_ShellObject_uyZ_aWevApi_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uyZ@aWevApi_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa1fa0f8191d54092be6e11b621f853956406a19ccde6085bf063f00472c2d73"

  strings:
    $s1 = "p.iid:94317eb3-7085-4449-8680-030e5a0890d3\" stEvt:when=\"2018-12-02T15:50:06+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}