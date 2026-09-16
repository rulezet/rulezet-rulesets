rule Virus_Hijack_Trojan_GenericKDZ_103285_269 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_269.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6556353890e67fa4079efa1551daf00b6d177c4831c2ea15dfc502188b9bc04f"

  strings:
    $s1 = "^(Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}