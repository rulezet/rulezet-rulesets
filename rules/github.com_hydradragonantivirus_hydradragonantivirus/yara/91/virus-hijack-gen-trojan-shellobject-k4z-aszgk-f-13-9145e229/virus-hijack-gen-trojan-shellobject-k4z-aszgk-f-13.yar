rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4d01946685a59df36949bd1d53ba6cc378fe4bd819f018c4444edfc389adf51"

  strings:
    $s1 = "eOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}