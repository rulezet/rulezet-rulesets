rule Virus_Hijack_Win32_Doboc_Gen_1_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Win32.Doboc.Gen.1_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebfa6dd2dace906d9f8cda7b39b958814300bef9e4f9ebc82c31aa9224a8acbf"

  strings:
    $s1 = "EnvY%%&:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}