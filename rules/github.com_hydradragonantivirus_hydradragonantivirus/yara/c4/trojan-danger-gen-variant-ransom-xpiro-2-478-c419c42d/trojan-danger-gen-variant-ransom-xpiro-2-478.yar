rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_478 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_478.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23071df922aaaabe7b34b8ccba01be5712d2f7aa55f8443a39f3624d373aec21"

  strings:
    $s1 = "Start Command Prompt with Ruby.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}