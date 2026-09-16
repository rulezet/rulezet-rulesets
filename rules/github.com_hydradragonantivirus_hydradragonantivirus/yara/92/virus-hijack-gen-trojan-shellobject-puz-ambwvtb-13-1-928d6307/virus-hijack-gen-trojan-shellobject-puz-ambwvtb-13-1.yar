rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d835b9d0d71bf9aeb639b48e57bcb94aebe0b824c3e8a45dca1962ff0781af27"

  strings:
    $s1 = "Cs<rEiT" fullword ascii
    $s2 = "``beat" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}