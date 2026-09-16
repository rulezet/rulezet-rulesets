rule Virus_Hijack_Gen_Trojan_ShellObject_g4X_aSzGK_f_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b185de2d1a0a1534de20a489aae8b01daa15826cfc80f6bb37cdb536c6921cf"

  strings:
    $s1 = "hAOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}