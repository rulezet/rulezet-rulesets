rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed3a176fba41267c612f15ada76e0853b5702b2498efbad2af0ea5928cd94564"

  strings:
    $s1 = "URprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii
    $s2 = "URprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}