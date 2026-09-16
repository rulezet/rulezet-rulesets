rule Virus_Hijack_Gen_Trojan_ShellObject_xyZ_aCEmdoo_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.xyZ@aCEmdoo_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6632f4a809fca7cd3257a2ce5dc6c6dde6bf6d6b6745c7b8df4146b013220f3"

  strings:
    $s1 = "/photoshop/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.co{/xap/1.0/sType/ResourceEvent#" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}