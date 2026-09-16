rule Virus_Hijack_Gen_Trojan_ShellObject_WyZ_aCEmdoo_43 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.WyZ@aCEmdoo_43.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23af98bfb351bb0c36e47b51a4dd1906d1f1402d83af0fdfcc8a17d79fed62a0"

  strings:
    $s1 = "p.iid:94317eb3-7085-4449-8680-030e5a0890d3\" stEvt:when=\"2018-12-02T15:50:06+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}