rule Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cfaca00a9b57ac5ee5f66ad5a48996afc9769b35880f192aeb0785e872a214a"

  strings:
    $s1 = "Rwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}