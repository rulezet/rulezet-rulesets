rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_a8_cJFh_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@a8!cJFh_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9c6ee244f1ea0fea3a7a093bea65efeb316e1abd7da93e4b94c6f3098a238be"

  strings:
    $s1 = "sOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}