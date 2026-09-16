import "pe"
rule _Trojan_Danger_Trojan_GenericKD_72853156_507_1_Trojan_Danger_Tro_313 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72853156_507_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_531_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e8147fb0b94a478ea44492236f653c9d8544240a9b5974c9009725ba8e09fd4"
    hash2       = "45ef71e418efdaa3324e5ca80927dd89d7b1fbd3b5233751aedf0659d1b6dd23"

  strings:
    $s1  = "dLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsaservice or to pay related taxes, materials and/or expenses. Learning credits are n" ascii
    $s2  = "or service that is subject to a discount or a promotion when you order the relevant product or service. The list price will be9o" ascii
    $s3  = "dLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsaemployee who has one or more benefit plans managed by the system or continues to b" ascii
    $s4  = "dLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsaemployee who has one or more benefit plans managed by the system or continues to b" ascii
    $s5  = "This agreement is valid for the order to which this agreement accompanies.sEzUJ6qEoVsEzUJ6qEoVsEzUDX9xSCi3MrDX9xSCi3MrDX9xSCi3Mr" ascii
    $s6  = "This agreement is valid for the order to which this agreement accompanies.sEzUJ6qEoVsEzUJ6qEoVsEzUDX9xSCi3MrDX9xSCi3MrDX9xSCi3Mr" ascii
    $s7  = "required to be licensed as systems; howeve" fullword ascii
    $s8  = "e paid through the system. For Time and" fullword ascii
    $s9  = "RETA IL LICENSE TERMS5vKlzMlZ6F5vKlzMlZ6F5vKlzMlZ6F5vKlzMlGz2YbINwH" fullword ascii
    $s10 = "dLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsaservice or to pay related taxes, materials and/or expenses. Learning credits are n" ascii
    $s11 = "or service that is subject to a discount or a promotion when you order the relevant product or service. The list price will be9o" ascii
    $s12 = "THOUGH WE DO NOT, " fullword ascii
    $s13 = "B. Applicability of AgreementXMdSxw5ZUDXMdSxw5ZUDXMdSxw5ZUDXMdSxwYbTkpIcD" fullword ascii
    $s14 = "by you to use the application programs whDAMA GES, INCLUDING CONSEQUENTIA L, LOST PROFITS, SPECIA L, INDIRECT, OR" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "8dacd0d6e8e1e47d867ec3346b3c00bc" and (8 of them)
    ) or (all of them)
}