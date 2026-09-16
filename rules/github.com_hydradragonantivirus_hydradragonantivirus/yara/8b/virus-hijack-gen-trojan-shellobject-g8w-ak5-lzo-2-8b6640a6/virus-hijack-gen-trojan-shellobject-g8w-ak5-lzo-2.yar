rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aK5_lZo_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aK5!lZo_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff936e2adf23c9276194b7978fe6560060f38f70bbdbdc886720533c77170b82"

  strings:
    $s1 = "6PUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}