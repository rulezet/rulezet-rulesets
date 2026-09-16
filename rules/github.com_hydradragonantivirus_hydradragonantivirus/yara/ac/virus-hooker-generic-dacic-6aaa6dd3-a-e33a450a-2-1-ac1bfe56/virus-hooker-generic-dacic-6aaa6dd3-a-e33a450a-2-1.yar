rule Virus_Hooker_Generic_Dacic_6AAA6DD3_A_E33A450A_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Generic.Dacic.6AAA6DD3.A.E33A450A_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dec8311a48326f246c83f299ddeca744c312a675c5d844b2a1167653ba3ae7e5"

  strings:
    $s1 = ".8 tEth" fullword ascii
    $s2 = "#x;ChAI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}