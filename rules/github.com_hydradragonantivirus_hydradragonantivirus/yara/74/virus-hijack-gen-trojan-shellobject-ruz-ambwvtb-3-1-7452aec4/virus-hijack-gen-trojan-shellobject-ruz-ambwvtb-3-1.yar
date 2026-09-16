rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_amBwvTb_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@amBwvTb_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f6cc13fe4d319ca8662de6fbf49734e8a09a5e80e117a7e4b7965f34d8778e9"

  strings:
    $s1 = ",;BURl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}