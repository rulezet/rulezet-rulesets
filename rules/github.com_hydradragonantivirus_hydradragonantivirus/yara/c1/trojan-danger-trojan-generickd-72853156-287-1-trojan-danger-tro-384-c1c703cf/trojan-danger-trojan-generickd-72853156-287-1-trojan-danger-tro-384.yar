import "pe"
rule _Trojan_Danger_Trojan_GenericKD_72853156_287_1_Trojan_Danger_Tro_384 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72853156_287_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_381_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_389_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81be3f735b2ee106d93a16fb49e3feced6b21e570b3a927a80a6b7da2080bc83"
    hash2       = "f0409b0022c3ba1ad3e0eee479c8cf2deb5bfd51b207781459175e419cc9f0e1"
    hash3       = "7e553c7f7927176ca6744aafc663a41fc5e0dbdbd73367614e6f4b1d19ea6f1a"

  strings:
    $s1  = "qamqqvaqqdSysqamqqvaqqdSysqamqqvaq1K Invoice Line: is defined as one thousand invoice line items processed by the program during" ascii
    $s2  = "Microsoft Corporation, A TTN: LCA ARBITRA TION, One Microsoft Way, Redmond, WA 98052-ysqamqqvaqqdSysqamqqvaqqdSysqemdvkceSysqamq" ascii
    $s3  = "qamqqvaqqdSysqamqqvaqqdSysqamqqvaq1K Invoice Line: is defined as one thousand invoice line items processed by the program during" ascii
    $s4  = "Management application from any source (not manually entered by licensed Order Management Users, Professional UsersSysqamqqvaqqd" ascii
    $s5  = "Management application from any source (not manually entered by licensed Order Management Users, Professional UsersSysqamqqvaqqd" ascii
    $s6  = "ysqamqqvaqqdSysqamqqvaqqExcept for actions for nonpayment or breach of Oracle" fullword ascii
    $s7  = "by Oracle from time to time without notice to you." fullword ascii
    $s8  = " a 12 month period. You" fullword ascii
    $s9  = "SysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaq" ascii
    $s10 = "Microsoft Corporation, A TTN: LCA ARBITRA TION, One Microsoft Way, Redmond, WA 98052-ysqamqqvaqqdSysqamqqvaqqdSysqemdvkceSysqamq" ascii
    $s11 = "by a cable provider; or (d) a live connected utility meter. The total number of Subscribers is equal to the aggregate of all typ" ascii
    $s12 = "RECOVERING DAMA GES FROM MICROSOFT, YOU CA N RECOVER ONLY DIRECT DAMA GES UPqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamq" ascii
    $s13 = "sentence or under the Indemnification section, you must pay within 30 days all amounts which have accrued prior to the end ofysq" ascii
    $s14 = "RECOVERING DAMA GES FROM MICROSOFT, YOU CA N RECOVER ONLY DIRECT DAMA GES UPqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamq" ascii
    $s15 = "sentence or under the Indemnification section, you must pay within 30 days all amounts which have accrued prior to the end ofysq" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "eb07ecdaa8721f4ce156a6f738b80831" and (8 of them)
    ) or (all of them)
}