rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_19 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62c459d9a9b82b2b042de32d153f9b9ac61ac086703d676b619a34457d214ab7"

  strings:
    $s1 = "84Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}