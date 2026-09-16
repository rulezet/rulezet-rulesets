rule Trojan_Danger_Trojan_GenericKD_72304918_86_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_86_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcf31b5646ee4780063bccaa29c51a27364981fe1dd067e53d864000c486bc25"

  strings:
    $s1 = ">University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}