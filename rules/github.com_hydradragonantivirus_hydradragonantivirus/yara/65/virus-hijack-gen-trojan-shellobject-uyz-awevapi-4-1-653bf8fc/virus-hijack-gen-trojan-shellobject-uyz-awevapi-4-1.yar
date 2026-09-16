rule Virus_Hijack_Gen_Trojan_ShellObject_uyZ_aWevApi_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uyZ@aWevApi_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "067333c0f5e2643fc62e025a0c84f62d355656d8aba57aad25818365e59fa2c5"

  strings:
    $s1 = "pe/ResourceEvent#\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmp:CreatorTool=\"Adobe Pho" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}