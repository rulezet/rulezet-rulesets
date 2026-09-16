rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "708a9a8eef0f00afd41141311a9f94666d258b0f55761dcedfd0f70c9ffab4ce"

  strings:
    $s1 = "myOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}