rule Virus_Hijack_Gen_Trojan_ShellObject_g4X_aSzGK_f_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb540b5fd6ca97ec809d4460bcb6c9c632acf345667c3e443778239ef7b9ffa1"

  strings:
    $s1 = "UOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}