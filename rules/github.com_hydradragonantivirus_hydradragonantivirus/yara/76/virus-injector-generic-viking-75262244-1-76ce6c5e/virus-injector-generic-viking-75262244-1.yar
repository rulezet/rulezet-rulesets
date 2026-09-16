rule Virus_Injector_Generic_Viking_75262244_1 {
  meta:
    description = "datamaliciousorder - file Virus.Injector_Generic.Viking.75262244_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0250d6a8f7525df71ce1f54bed00464ae90f040fb8540089c99c2dbfff71eed9"

  strings:
    $s1 = "Compiled AutoIT Script by CWAutComp v2.16" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}