rule Virus_Hijack_Gen_Trojan_ShellObject_pyZ_aeWgNZc_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pyZ@aeWgNZc_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "edc441b474545ad303781d9713961dc83be2045e811c3b07a4949a05d0711001"

  strings:
    $s1 = "sHor{fB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}