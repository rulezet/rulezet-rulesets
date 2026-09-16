rule Trojan_Autorun_Trojan_GenericKDZ_94847_305_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_305_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c373c1c293ff33ab4ed4bfc7851b573cbf8e89d35577f9488c49ce87c534ba42"

  strings:
    $s1 = "xProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}