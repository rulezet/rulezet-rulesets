import "pe"
rule _VirusShareBackDoorBladabindi13678_2_1_VirusShareBackDoorBladabi_30 {
  meta:
    description = "datamaliciousorder - from files VirusShareBackDoorBladabindi13678_2_1.vir, VirusShareBackDoorBladabindi3459_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a235f322e3a94f07dd5018c7d43b353592fe9550a4bc17622b200b0c2aafba31"
    hash2       = "7e93386b0f4aee6ba5dba9b29ebbf2926c99a83ff57e4f7719d652e2b0ba301f"

  strings:
    $s1 = "List<HK" fullword ascii
    $s2 = "List<aE" fullword ascii
    $s3 = "Current((J" fullword ascii
    $s4 = "Count 'G" fullword ascii
    $s5 = "List @I" fullword ascii
    $s6 = "Count,VI" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f9e81afd2870aaecd8ace36b2893b1d3" and (all of them)
    ) or (all of them)
}