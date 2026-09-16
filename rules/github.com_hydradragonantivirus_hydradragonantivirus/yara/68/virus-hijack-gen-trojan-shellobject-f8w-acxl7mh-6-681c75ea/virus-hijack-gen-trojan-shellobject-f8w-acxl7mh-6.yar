rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aCXl7mh_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCXl7mh_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ad3eed96e5d640a0caa4e6c375856d7432c293498a9c7fb09f00a121626ac64"

  strings:
    $s1 = "nOrders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}