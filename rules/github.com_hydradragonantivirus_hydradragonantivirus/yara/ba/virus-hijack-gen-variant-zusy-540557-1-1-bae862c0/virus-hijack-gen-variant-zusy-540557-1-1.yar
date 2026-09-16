rule Virus_Hijack_Gen_Variant_Zusy_540557_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Zusy.540557_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d14b6569efc5b47c7168d656215c76dbfe88914a9b4b573178f19ad3cfcfb37d"

  strings:
    $s1 = "/photoshop/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.co{/xap/1.0/sType/ResourceEvent#" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}