rule Trojan_Autorun_Trojan_GenericKDZ_94847_225_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_225_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e58b8f033cbfff07525f9253451701e61ad575cd793b9bd5f37469e60675ece9"

  strings:
    $s1 = "=ZProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}