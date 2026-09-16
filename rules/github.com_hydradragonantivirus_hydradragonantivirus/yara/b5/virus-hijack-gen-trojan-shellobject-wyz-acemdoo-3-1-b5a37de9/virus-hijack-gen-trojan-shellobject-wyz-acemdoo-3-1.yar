rule Virus_Hijack_Gen_Trojan_ShellObject_WyZ_aCEmdoo_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.WyZ@aCEmdoo_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08c64da775d26fd4d1f3a95b28f383d7a9c55e09ae2d1badd6fcad9cfd2b59b4"

  strings:
    $s1 = "/photoshop/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.co{/xap/1.0/sType/ResourceEvent#" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}