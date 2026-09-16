rule Virus_Hijack_Gen_Trojan_ShellObject_k8Z_aqgEuSk_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8Z@aqgEuSk_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "290c9832d92785672c3b58c9004b1d1161d1ac7a116a9b7abf6ec63456113716"

  strings:
    $s1 = "O<MoON" fullword ascii
    $s2 = "N@wONg" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}