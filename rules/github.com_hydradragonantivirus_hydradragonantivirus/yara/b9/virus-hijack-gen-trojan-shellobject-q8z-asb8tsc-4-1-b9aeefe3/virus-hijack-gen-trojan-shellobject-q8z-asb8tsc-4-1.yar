rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aSb8tSc_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aSb8tSc_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4c26d6264089a12366dccf6849d6b71d7f04c4599ffe6ebab0c89fa77d10c3f"

  strings:
    $s1 = "wiNT?'" fullword ascii
    $s2 = "BroG`P" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}