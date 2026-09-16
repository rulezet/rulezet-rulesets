rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b31216dc6e1cb116759f1219ee21b2cda7d1fc576876010aa51027210932ec31"

  strings:
    $s1 = "mprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii
    $s2 = "mprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii
    $s3 = "Wl`SOry[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}