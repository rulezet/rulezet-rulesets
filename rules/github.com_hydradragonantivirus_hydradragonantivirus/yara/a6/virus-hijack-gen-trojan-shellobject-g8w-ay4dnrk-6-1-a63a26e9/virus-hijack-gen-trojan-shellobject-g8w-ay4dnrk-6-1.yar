rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e764d6d6c109824b25ef91b4d9fedd50ce87c100e8dadd8117d7c6fbbfd71b7"

  strings:
    $s1 = "Collet" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}