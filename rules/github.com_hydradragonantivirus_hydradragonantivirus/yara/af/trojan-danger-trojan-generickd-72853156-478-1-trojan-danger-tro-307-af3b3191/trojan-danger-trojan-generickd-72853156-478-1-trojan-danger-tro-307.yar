import "pe"
rule _Trojan_Danger_Trojan_GenericKD_72853156_478_1_Trojan_Danger_Tro_307 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72853156_478_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_489_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2875912aa14f7ae9110e89e1c785b3fe1a05a5086af6ea2968818b551527fbc8"
    hash2       = "21d324cf0702a53551b9979c3b56c441845dcee755307aa2804bd3b4dbc2cddb"

  strings:
    $s1  = "of the breach, the other party may terminhttp://oracle.com/contracts, and may be updated by Oracle from time to time without not" ascii
    $s2  = "of the breach, the other party may terminhttp://oracle.com/contracts, and may be updated by Oracle from time to time without not" ascii
    $s3  = "This agreement (together with terms accompanying any software supplements, updates, and servicesDwbFL9w0FJDwlIHDpkd4N3lIHDpkd4N3" ascii
    $s4  = "This agreement (together with terms accompanying any software supplements, updates, and servicesDwbFL9w0FJDwlIHDpkd4N3lIHDpkd4N3" ascii
    $s5  = "For new or unsupported customers, please contact your Oracle Account Manager for this information.vxugtUwEF7vxugtUwEF7vxuxwtP54k" ascii
    $s6  = "For new or unsupported customers, please contact your Oracle Account Manager for this information.vxugtUwEF7vxugtUwEF7vxuxwtP54k" ascii
    $s7  = "dLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsawith your employees and agents that protect the confidentiality and proprietary ri" ascii
    $s8  = "operate with Oracle" fullword ascii
    $s9  = "dLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsawith your employees and agents that protect the confidentiality and proprietary ri" ascii
    $s10 = "Application Read-Only User: is defined as an individual authorized by you to run only queries or reports against theNP" fullword ascii
    $s11 = "between you and the computer manufacturer or software installer that distributes the Microsoft OfficeOracle Finance Division Con" ascii
    $s12 = "of the breach, the other party may terminUpon 45 days written notice, Oracle may audit your use of the programs. You agree to co" ascii
    $s13 = "between you and the computer manufacturer or software installer that distributes the Microsoft OfficeOracle Finance Division Con" ascii
    $s14 = "Neither of us shall be responsible for failure or delay of performance if caused by: an act of war, hostility, or sabotage; act " ascii
    $s15 = "dLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsaproof of purchase from an authorized electronic supplier of genuine Microsoft soft" ascii
    $s16 = "of the breach, the other party may terminUpdates or Product Support for the same number of licenses for the same programs, for t" ascii
    $s17 = "dLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsaproof of purchase from an authorized electronic supplier of genuine Microsoft soft" ascii
    $s18 = "above will not be applied to such taxes, materials and/or expenses. Learning credits are valid for a pService Order Line license" ascii
    $s19 = "of the breach, the other party may terminUpdates or Product Support for the same number of licenses for the same programs, for t" ascii
    $s20 = "above will not be applied to such taxes, materials and/or expenses. Learning credits are valid for a pService Order Line license" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "54e997e4a8ce64b9d62c13920666b893" and (8 of them)
    ) or (all of them)
}