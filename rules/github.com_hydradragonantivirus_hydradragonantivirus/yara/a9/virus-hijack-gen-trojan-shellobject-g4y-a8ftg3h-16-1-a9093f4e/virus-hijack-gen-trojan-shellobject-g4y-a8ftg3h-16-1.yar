rule Virus_Hijack_Gen_Trojan_ShellObject_g4Y_a8fTg3h_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4Y@a8fTg3h_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7dbdc92a1d8c28935e36c18f2e9967735d9a82831dd86d09a6b1b0367ea0a88"

  strings:
    $s1 = "FRIz']," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}