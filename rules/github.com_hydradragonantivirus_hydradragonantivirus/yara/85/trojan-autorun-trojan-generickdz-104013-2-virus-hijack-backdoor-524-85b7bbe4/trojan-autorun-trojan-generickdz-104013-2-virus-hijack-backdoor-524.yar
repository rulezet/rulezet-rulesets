import "pe"
rule _Trojan_Autorun_Trojan_GenericKDZ_104013_2_Virus_Hijack_Backdoor_524 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKDZ.104013_2.vir, Virus.Hijack_Backdoor.Hangup.B_312_1.vir, Virus.Hijack_Backdoor.Hangup.B_37_1.vir, Virus.Hijack_Backdoor.Hangup.B_38_1.vir, Virus.Hijack_Backdoor.Hangup.B_42_1.vir, Virus.Hijack_Backdoor.Hangup.B_45_1.vir, Virus.Hijack_Backdoor.Hangup.B_48_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aeed1ba6715a0fcaf520b8bd4c42ad578cbb69e769f141a5ec0c6ed90f272a8a"
    hash2       = "a779c390220c8226d9b53f7806ab92565912ce04d0f196cbcd086123d6867921"
    hash3       = "206f767b7cffca3855b47864e16c6b12f78625cbf9b46760c541dc1410f1867a"
    hash4       = "7c8195cbc7809c1de0a63cee7cdc6e755f332d562cd5f53a8f850249ba9d326c"
    hash5       = "d6016725cb409d6356f987b694df16f07c9a20e11a03250436b41b0d19b5ebb6"
    hash6       = "a501212425168cc20fab7a3a37dc1817a354ce8da68148499bc82983696e3ebb"
    hash7       = "754b1fcd20330d12ee41aca9ba099beb0a8f14f0ffe18a8e94293d84c37acb48"

  strings:
    $x1 = "Processor basis may be accessed by your internal users (including agents and contrNon Employee User - External: is defined as an" ascii
    $x2 = "Processor basis may be accessed by your internal users (including agents and contrNon Employee User - External: is defined as an" ascii
    $s3 = "Processor basis may be accessed by your internal users (including agents and contr" fullword ascii
    $s4 = " individual, who is not your employee, contractor or outsourcer, authorized" fullword ascii
    $s5 = " four hundred" fullword ascii
    $s6 = "defined as one million U.S. dollars (Seven hundred and seventy-two thousand four hundred" fullword ascii
    $s7 = " dollars (Seven hundred and seventy-two thousand four hundred" fullword ascii
    $s8 = " review the policies prior to entering into the ordering document for the applicable services. You" fullword ascii
    $s9 = "into the ordering document for the applicable services. You" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "797dd633c22af2b1fa08a15f105f2163" and (1 of ($x*) and all of them)
    ) or (all of them)
}