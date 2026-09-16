rule Virus_Hijack_Gen_Trojan_ShellObject_g4X_aSzGK_f_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2de39a3d111e36e84865f42a533b8be38d77798690f98b79a3c5aef767320fa2"

  strings:
    $s1 = "sZOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}