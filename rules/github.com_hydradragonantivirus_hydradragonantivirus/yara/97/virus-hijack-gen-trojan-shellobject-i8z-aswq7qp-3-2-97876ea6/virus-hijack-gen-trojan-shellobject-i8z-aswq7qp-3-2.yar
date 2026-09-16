rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aSWq7Qp_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aSWq7Qp_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa3b1e6f09fafb0fb620a294ce11e46d9621965aeeee841600d7f9242434e97d"

  strings:
    $s1 = "Rich*/" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}