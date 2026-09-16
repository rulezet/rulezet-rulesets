rule _Trojan_Hooker_Trojan_Agent_AQNV_1_Trojan_Hooker_Trojan_GenericK_361 {
  meta:
    description = "datamaliciousorder - from files Trojan.Hooker_Trojan.Agent.AQNV_1.vir, Trojan.Hooker_Trojan.GenericKDZ.96830_7_1.vir, Trojan.Hooker_Trojan.GenericKDZ.96830_8_1.vir, Trojan.Hooker_Win32.Floxif.A_10_1.vir, Trojan.Hooker_Win32.Floxif.A_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b8d304edafba3c3aaae7edb105b04995678b2b3d280698d6eaaf92c9935bd36"
    hash2       = "5131288c4bb3c7930f5ac9b04e90c4e66abd9ea1f6c25cc7746790137edd514b"
    hash3       = "a6f6a1b9fa5e7bf28a255710315bcbe870978aa2f04b88511d17dd17c50cb97f"
    hash4       = "17593a14e0aff92a6a115f58568483c0ff318c055b69647ed9fb75091ab9ddbd"
    hash5       = "8f9186132d5716c1718beb3b87742f5603a033d316df02dad046193cf1c8a7fe"

  strings:
    $s1  = "abor-executable code" fullword ascii
    $s2  = "h system" fullword ascii
    $s3  = "many links" fullword ascii
    $s4  = "f domain of f" fullword ascii
    $s5  = "Resource dead" fullword ascii
    $s6  = "Broken pi" fullword ascii
    $s7  = "orage acces8rithmetic er" fullword ascii
    $s8  = "No locks avail@" fullword ascii
    $s9  = ". would occur/ posi^O0|" fullword ascii
    $s10 = "Write<" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}