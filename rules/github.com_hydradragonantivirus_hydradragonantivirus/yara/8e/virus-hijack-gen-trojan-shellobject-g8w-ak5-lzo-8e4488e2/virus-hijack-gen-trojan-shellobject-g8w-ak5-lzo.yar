rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aK5_lZo {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aK5!lZo.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8210058a8d671ad02167fbe962b308c0f39e12b575441bf2b03e498cdafd74b6"

  strings:
    $s1 = "G&University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}