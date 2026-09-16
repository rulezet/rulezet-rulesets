rule Virus_Danger_Gen_Trojan_ShellObject_u4Z_ay8bj9g {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.u4Z@ay8bj9g.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11b7f33dad0271129e711493b8a57fbc19eaf3d8444d682e9338bcf4a01c0f38"

  strings:
    $s1 = "Imust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}