rule Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aqOJzSd_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqOJzSd_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24e3f9f75b3e5167debeb4bea331c6f34691000c56e13e477d996e767dffcae2"

  strings:
    $s1 = "pe/ResourceEvent#\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmp:CreatorTool=\"Adobe Pho" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}