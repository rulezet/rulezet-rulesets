rule Virus_Hijack_Gen_Trojan_ShellObject_w8Z_ae_1SNh_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.w8Z@ae@1SNh_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce4024e3609bad8d8049d16a1b0c65c45541012f4234a1a4c209fe7e6bbf2644"

  strings:
    $s1 = "p.iid:94317eb3-7085-4449-8680-030e5a0890d3\" stEvt:when=\"2018-12-02T15:50:06+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}