rule Virus_Hooker_Generic_Dacic_6AAA6DD3_A_E33A450A_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Generic.Dacic.6AAA6DD3.A.E33A450A_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdcb214f2034c243b77470cdb5f5f2104677ef5889e356723b1885ebf2c92e78"

  strings:
    $s1 = "Beek)J" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}