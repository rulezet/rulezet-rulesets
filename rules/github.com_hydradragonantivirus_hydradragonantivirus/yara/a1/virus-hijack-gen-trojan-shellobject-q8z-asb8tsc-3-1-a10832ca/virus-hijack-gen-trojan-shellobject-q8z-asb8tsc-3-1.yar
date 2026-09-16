rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aSb8tSc_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aSb8tSc_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cbe6daf486693e3220aec0699bf53a1804ab18984c3ca1bf64e6751f602ab1e"

  strings:
    $s1 = "VinE]V" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}