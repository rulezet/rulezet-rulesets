rule Trojan_Danger_Trojan_GenericKD_72677122_308_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_308_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af8b7b42a3f1ebc7d64a9f36614bbb2c9a448b35091207d36b12ebe1506e71ec"

  strings:
    $s1 = "6the right to run one copy only on the computer with which you acquired the software (the licensed" fullword ascii
    $s2 = "6pages initiated remotely by the program (measured explicitly in the program as Received Data Collection Instruments) during a" fullword ascii
    $s3 = "court (Section B.3) or in arbitration (Section B.4). The one-year period begins when the claim or disputerect product thereof) w" ascii
    $s4 = "6You may not assign this agreement or give or transfer the programs and/or any services or an interest in them to another" fullword ascii
    $s5 = "ill be exported, directly or indirectly, in violation" fullword ascii
    $s6 = "6a single server or multiple servers, regardless of whether or not the individual is actively using the programs at any given ti" ascii
    $s7 = "6a single server or multiple servers, regardless of whether or not the individual is actively using the programs at any given ti" ascii
    $s8 = "court (Section B.3) or in arbitration (Section B.4). The one-year period begins when the claim or disputerect product thereof) w" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}