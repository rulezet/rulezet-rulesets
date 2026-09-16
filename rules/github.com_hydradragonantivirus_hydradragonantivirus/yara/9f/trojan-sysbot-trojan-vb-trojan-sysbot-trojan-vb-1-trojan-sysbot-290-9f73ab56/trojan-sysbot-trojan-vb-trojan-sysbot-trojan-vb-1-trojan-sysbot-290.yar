import "pe"
rule _Trojan_Sysbot_Trojan_VB_Trojan_Sysbot_Trojan_VB_1_Trojan_Sysbot_290 {
  meta:
    description = "datamaliciousorder - from files Trojan.Sysbot_Trojan.VB.vir, Trojan.Sysbot_Trojan.VB_1.vir, Trojan.Sysbot_Trojan.VB_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b6cc7f106c9d5d9c1d12fad4ba7fe4fcdcd3b6f303f7596070692177da0b975"
    hash2       = "13678301ab64a0459efd2aca48d594b0d9119447d1ca70aabd60e6a236369efe"
    hash3       = "ad9e54fdfc037b9ecb610d423dddf73dbe205a713f72e6643a43a949f6aed6ae"

  strings:
    $s1 = "<Instant>" fullword wide
    $s2 = "<Attack>" fullword wide
    $s3 = "Remark for " fullword wide
    $s4 = "7*X(&OVal" fullword wide
    $s5 = "<Mail>" fullword wide
    $s6 = "<Click>" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "98f67c550a7da65513e63ffd998f6b2e" and (all of them)
    ) or (all of them)
}