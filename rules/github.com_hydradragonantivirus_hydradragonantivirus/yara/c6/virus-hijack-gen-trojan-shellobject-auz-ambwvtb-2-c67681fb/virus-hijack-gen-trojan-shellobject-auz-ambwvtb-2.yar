rule Virus_Hijack_Gen_Trojan_ShellObject_AuZ_amBwvTb_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.AuZ@amBwvTb_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c315a54295dedbd4099918a1bb1e9c690824518cf75621d8b295df577667b67d"

  strings:
    $s1 = "3g:9f7i8;oBAn?q@CwJIvGyHK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}