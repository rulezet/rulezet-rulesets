rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_a4IOpRm_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@a4IOpRm_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7597368e9c2b1df16c2f3b9d5a72eaa8aab31a256347c823bc05e1423a558aa7"

  strings:
    $s1 = "@you received the software, and also any Microsoft updates, supplements, and services for the software," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}