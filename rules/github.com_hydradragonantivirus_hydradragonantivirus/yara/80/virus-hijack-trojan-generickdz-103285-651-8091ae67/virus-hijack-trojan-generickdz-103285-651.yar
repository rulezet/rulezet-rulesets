rule Virus_Hijack_Trojan_GenericKDZ_103285_651 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_651.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "561aac017b2e8e730105ad13af3eca7318302b6791ff6f7c8421ffda90374746"

  strings:
    $s1 = "I~Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}