rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "965e08a48e7170c1cf3ead5170d1735b98aac9b56ae9de82df8bb230119e78d2"

  strings:
    $s1 = "hprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii
    $s2 = "hprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}