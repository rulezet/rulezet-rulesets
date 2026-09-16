rule Virus_Hijack_Gen_Trojan_ShellObject_uGZ_ayM4QWg_37_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_37_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c72d9270c088543fefbd3a7bf6fe4861a9393bccf13decdb7f75d008a780700"

  strings:
    $s1 = "VJava(TM) SE Runtime Environment 6 Update 3" fullword wide
    $s2 = "Java(TM) Platform SE 6 U30" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}