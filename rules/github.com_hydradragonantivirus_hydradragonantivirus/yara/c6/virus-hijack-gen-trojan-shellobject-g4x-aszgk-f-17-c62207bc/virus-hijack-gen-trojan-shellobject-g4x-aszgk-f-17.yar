rule Virus_Hijack_Gen_Trojan_ShellObject_g4X_aSzGK_f_17 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28fab6857d32fe45dc8e6d242b6165239473b90c4f6ec6427233254495e25064"

  strings:
    $s1 = "yOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}