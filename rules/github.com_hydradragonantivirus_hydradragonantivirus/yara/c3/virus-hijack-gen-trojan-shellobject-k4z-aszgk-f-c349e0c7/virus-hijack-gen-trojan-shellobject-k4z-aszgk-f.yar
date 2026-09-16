rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30bef980916aa3faa6470e4fe1fcc86c1a2b950606342c9d316b9a445ef7c2eb"

  strings:
    $s1 = "mOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}