rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_a0kuefc_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@a0kuefc_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91654987a19da62465c305da03c26a88b136975bb1f113aad609eb1830a3fcf2"

  strings:
    $s1 = "url.org/dc/elements/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/" ascii
    $s2 = "atorTool=\"Adobe Photoshop CC 2018 (Windows)\" xmp:CreateDate=\"2018-12-02T15:50:06+08:00\" xmp:ModifyDate=\"2019-01-07T19:44:27" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}