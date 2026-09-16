rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4692ba12f3bfbc84b0d905a3c19d06d054052120022a5c1ab8ffb61e2d2bd5c6"

  strings:
    $s1 = "(NOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}