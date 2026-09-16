rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_amMcCQb {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@amMcCQb.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c1fd1b158baef223bfbead54d2723e951156f64bba1ef812b3f3df7e3151d1b"

  strings:
    $s1 = "Ywhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}