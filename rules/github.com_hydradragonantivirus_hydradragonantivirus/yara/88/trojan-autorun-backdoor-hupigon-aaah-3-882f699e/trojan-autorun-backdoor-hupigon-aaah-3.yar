rule Trojan_Autorun_Backdoor_Hupigon_AAAH_3 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Backdoor.Hupigon.AAAH_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2360716c3b7250ecd5814ca97f91ec214bc3c3dcc9eee0cebf7bfdb0f3231ab"

  strings:
    $s1 = "Mellon Financial Corporation" fullword wide
    $s2 = " 2018 Mellon Financial Corporation" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}