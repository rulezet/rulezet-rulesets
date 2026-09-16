rule Virus_Hijack_Gen_Trojan_ShellObject_s8Z_aGRF3ml_10_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.s8Z@aGRF3ml_10_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "696c83c3b079e10c1a90bd223073119b88a9252d52fc2e0f8c6965198529665a"

  strings:
    $s1 = "Java(TM) Platform SE 8 U221" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}