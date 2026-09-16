rule Virus_Hijack_Trojan_Agent_DQQO_306_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_306_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "445f812e387b304b0ca63580aee19b66caae034de109cac78898c094b327eb81"

  strings:
    $s1 = "\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmp:Crea" fullword ascii
    $s2 = "c/elements/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:s" ascii
    $s3 = "orTool=\"Adobe Photoshop CC 2018 (Windows)\" xmp:CreateDate=\"2018-12-02T15:50:06+08:00\" xmp:ModifyDate=\"2019-01-07T19:44:27+0" ascii
    $s4 = "orTool=\"Adobe Photoshop CC 2018 (Windows)\" xmp:CreateDate=\"2018-12-02T15:50:06+08:00\" xmp:ModifyDate=\"2019-01-07T19:44:27+0" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}