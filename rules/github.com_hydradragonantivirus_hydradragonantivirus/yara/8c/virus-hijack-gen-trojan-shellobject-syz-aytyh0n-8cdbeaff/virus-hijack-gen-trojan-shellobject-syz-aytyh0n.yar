rule Virus_Hijack_Gen_Trojan_ShellObject_syZ_ayTyh0n {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.syZ@ayTyh0n.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d57f44fc2c839e3012fb356d28c79a8aa1e055bded092992d4c9e1fc454e471e"

  strings:
    $s1 = "Cstring too long" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}