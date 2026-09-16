rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aCXl7mh_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCXl7mh_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8122e1fdbdcafabb1254597ee199502159edbc1041b8981d47b481d17879d456"

  strings:
    $s1 = "COrders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}