import "pe"
rule _Virus_Hijack_Dropped_Backdoor_Padodor_BJ_79_1_Virus_Hijack_Drop_135 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Dropped.Backdoor.Padodor.BJ_79_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_8_1.vir, Virus.Hijack_Trojan.Agent.GCAX.vir, Virus.Hijack_Trojan.Agent.GCAX_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e5680973d120266108b074724e9f24b4228e1e43d15221f2ed312063c481bd0"
    hash2       = "f44847d285e099c7138e0ad99a71f7f0915eb8b92442cd33fb37dc0a54ef5b12"
    hash3       = "b7c560e8b7b959aadf1fba5c94cdb303d5d121dff1fc7e931ae23c8e846da00b"
    hash4       = "23e2115cc17a43ba293bde058c32bafff832928f3ba4c876bee2eef55d37af9e"

  strings:
    $s1 = "synapticula" fullword wide
    $s2 = "Glabellum" fullword wide
    $s3 = "Panda Security S.L1>0<" fullword ascii
    $s4 = "Panda Security S.L0" fullword ascii
    $s5 = "Hysterically" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "a1477f62efa130779fcb2868cf890b42" and (all of them)
    ) or (all of them)
}