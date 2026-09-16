rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_a4IOpRm_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@a4IOpRm_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0a185860dceaf05870ac5a9d0543bef8983f611c4bd758bc653fd604dded115"

  strings:
    $s1 = "%Vyou received the software, and also any Microsoft updates, supplements, and services for the software," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}