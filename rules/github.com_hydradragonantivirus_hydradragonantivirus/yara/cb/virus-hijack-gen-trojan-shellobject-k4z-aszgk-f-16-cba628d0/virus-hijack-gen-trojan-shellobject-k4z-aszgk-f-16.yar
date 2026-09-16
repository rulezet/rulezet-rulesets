rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "140babde716e811b368b12d73fd09abf7ade1a3052e2df3fc06cd4a9577a290c"

  strings:
    $s1 = "SOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}