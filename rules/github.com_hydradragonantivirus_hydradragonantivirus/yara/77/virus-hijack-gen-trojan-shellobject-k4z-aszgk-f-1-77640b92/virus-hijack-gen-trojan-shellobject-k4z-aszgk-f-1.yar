rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b2d56164af6127f4442ae1c17ad5ad7b533393ddda4943d3547affc62e76aec"

  strings:
    $s1 = "'Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}