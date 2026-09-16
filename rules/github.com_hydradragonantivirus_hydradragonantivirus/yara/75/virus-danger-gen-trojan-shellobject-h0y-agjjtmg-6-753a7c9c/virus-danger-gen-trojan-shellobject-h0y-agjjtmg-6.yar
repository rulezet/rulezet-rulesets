rule Virus_Danger_Gen_Trojan_ShellObject_h0Y_aGjJTmg_6 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.h0Y@aGjJTmg_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb1689c47efa61f7b0ce29971362e078b08b256a15126f3a8e658ec0be93f78e"

  strings:
    $s1 = "Applications National Language Support (NLS) Supplement CD Packs:`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}