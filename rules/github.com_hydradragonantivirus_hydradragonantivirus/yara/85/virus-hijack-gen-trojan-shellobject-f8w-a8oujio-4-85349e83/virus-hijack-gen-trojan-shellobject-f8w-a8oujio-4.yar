rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a8oUJio_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oUJio_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "269eefde5d4e933ed11b6eff1ff535f11b6a624586f1f009e99c1e7b80c8beff"

  strings:
    $s1 = "Oc Gore" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}