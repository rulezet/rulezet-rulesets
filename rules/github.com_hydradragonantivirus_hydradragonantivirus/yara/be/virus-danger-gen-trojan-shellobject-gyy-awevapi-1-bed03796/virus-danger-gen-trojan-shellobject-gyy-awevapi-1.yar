rule Virus_Danger_Gen_Trojan_ShellObject_gyY_aWevApi_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.gyY@aWevApi_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50cd32a57836969f859a8f79a609a9a460c94537008a55f86cab6863ad69e27f"

  strings:
    $s1 = "TWiCK[9" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}