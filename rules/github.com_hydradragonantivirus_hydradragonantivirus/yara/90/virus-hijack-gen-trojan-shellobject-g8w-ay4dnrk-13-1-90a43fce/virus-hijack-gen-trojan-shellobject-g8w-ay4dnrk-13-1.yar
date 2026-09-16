rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d1b037492110dfb110d6e84a434a8ba179a54794e75a4881911474d81969bfe"

  strings:
    $s1 = "Groundsman" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}