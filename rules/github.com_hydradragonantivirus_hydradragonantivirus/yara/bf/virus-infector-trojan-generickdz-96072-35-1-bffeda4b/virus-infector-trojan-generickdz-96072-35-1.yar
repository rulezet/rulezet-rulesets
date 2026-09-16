rule Virus_Infector_Trojan_GenericKDZ_96072_35_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Trojan.GenericKDZ.96072_35_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1299c520a36d6304c4472fc8407b260048ca26a18b0d4ac5bc77a8e14ad3119"

  strings:
    $s1 = ":stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmp:CreatorTool=\"Adobe Pho" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}