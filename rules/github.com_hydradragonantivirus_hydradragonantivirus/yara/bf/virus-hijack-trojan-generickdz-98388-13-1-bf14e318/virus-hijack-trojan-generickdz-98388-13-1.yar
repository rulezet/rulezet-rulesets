rule Virus_Hijack_Trojan_GenericKDZ_98388_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d2366f43aa51bfe14f95d42879fd390f277c26b08fc8067b881e25882c95753"

  strings:
    $s1 = " <QuIb" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}