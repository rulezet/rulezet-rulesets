import "pe"
rule _Virus_Hijack_Trojan_GenericKDZ_105924_197_1_Virus_Hijack_Trojan_241 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.GenericKDZ.105924_197_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_201_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_232_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd5b2af25b2575a52455955695fe553d6e9f370a29ee4d2d94a9b67a0018810c"
    hash2       = "7898240223128514c4c398dfc326e36d4fa94fb54ae3519b0947af8331bbea41"
    hash3       = "f04b84d38dd6c4b89513643e3360b2da0a8481913486f065caff7fd4aa606615"

  strings:
    $s1  = "Created by MIDL version 7.00.0499 at Wed Jan 20 23:54:23 2010" fullword ascii
    $s2  = "CurVer = s 'SearchIntegrationExe.CImeSearchIntegration.1'" fullword ascii
    $s3  = "IME 2010 Search Provider Settings" fullword wide
    $s4  = "Microsoft Office IME 2010 " fullword wide
    $s5  = "IME 2010 Add Search Provider" fullword wide
    $s6  = "IME 2010 Search Provider" fullword wide
    $s7  = "\"Microsoft Office IME 2010 " fullword wide
    $s8  = "\"IME search modul" fullword wide
    $s9  = "SearchIntegrationExe.CImeSearchIntegration.1 = s 'CImeSearchIntegration Class'" fullword ascii
    $s10 = "ForceRemove {c6544e9d-b344-48d6-a985-e67efb51d922} = s 'CImeSearchIntegration Class'" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "c4998075f1324ce0f644f12a548d76b1" and (all of them)
    ) or (all of them)
}