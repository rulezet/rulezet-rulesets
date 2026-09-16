rule Virus_Injector_Generic_Viking_33336338 {
  meta:
    description = "datamaliciousorder - file Virus.Injector_Generic.Viking.33336338.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cfb758bc8d779a7e4f3f549286ac83c8b98d5104f3efa056d8729462bf1645c"

  strings:
    $s1 = "aLky;," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}