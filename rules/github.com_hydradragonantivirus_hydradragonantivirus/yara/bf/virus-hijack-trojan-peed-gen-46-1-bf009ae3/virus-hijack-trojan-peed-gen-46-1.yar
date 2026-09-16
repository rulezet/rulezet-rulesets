rule Virus_Hijack_Trojan_Peed_Gen_46_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_46_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "901e8e18ca6d37702b9bac44e47795463639db795271f1223997eb82bdad3583"

  strings:
    $s1 = ",|!Qoph'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}