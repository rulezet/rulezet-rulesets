import "pe"
rule _Trojan_Hooker_Gen_Trojan_ProcessHijack_4s3baGODL8ai_Trojan_Hook_38 {
  meta:
    description = "datamaliciousorder - from files Trojan.Hooker_Gen.Trojan.ProcessHijack.4s3baGODL8ai.vir, Trojan.Hooker_Trojan.Ransom.CFC.vir, Virus.Hijack_Backdoor.Hangup.B_55_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3eba91226098a7357af6ca072807be7bfb5580a889972efa0534f44178845a3"
    hash2       = "274b182c9d81504a4d47967d6856816f03e39e0f8ac5d98711180d4779bafa77"
    hash3       = "759487f7b3e99d671981c039d7724ff559556c42a29feeb518451333b69139a0"

  strings:
    $s1  = "SELECT * FROM logins" fullword ascii
    $s2  = "/n:%temp%\\ellocnak.xml" fullword wide
    $s3  = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" fullword wide
    $s4  = "            <source location=\"%configsetroot%\\Windows6.0-KB929761-x86.CAB\" />" fullword ascii
    $s5  = "An assertion condition failed" fullword ascii
    $s6  = "Could not decrypt" fullword wide
    $s7  = "CLOt?2" fullword ascii
    $s8  = "A pure virtual function was called. This is a fatal error, and indicates a serious error in the implementation of the applicatio" ascii
    $s9  = "A pure virtual function was called. This is a fatal error, and indicates a serious error in the implementation of the applicatio" ascii
    $s10 = "XF]keNO" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "676f4bc1db7fb9f072b157186a10179e" and (all of them)
    ) or (all of them)
}