rule Virus_Hijack_Gen_Trojan_ShellObject_OWZ_aCIJdog_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.OWZ@aCIJdog_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d97947e18bd22451a39ad07c58f9fd8eeb50888efe806e8b6fcefb381d04d42"

  strings:
    $s1 = "[+]Got the address to write 0x%x" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}