rule Virus_Hijack_Trojan_Pws_Online_AGC_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Pws.Online.AGC_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "104ddedab6a5b6ef5df89200e65234d6515969a3753e4518d7b2685852adf35a"

  strings:
    $s1 = "cReA@)K" fullword ascii
    $s2 = "fb)WRaN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}