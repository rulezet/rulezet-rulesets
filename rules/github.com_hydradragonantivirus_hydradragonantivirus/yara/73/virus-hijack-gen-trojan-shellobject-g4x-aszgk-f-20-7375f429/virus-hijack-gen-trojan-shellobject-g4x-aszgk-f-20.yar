rule Virus_Hijack_Gen_Trojan_ShellObject_g4X_aSzGK_f_20 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_20.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a9809b6d62b342173bd2afd288ceae64b59f98377d77fe7d554230f7431c295"

  strings:
    $s1 = "#5Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}