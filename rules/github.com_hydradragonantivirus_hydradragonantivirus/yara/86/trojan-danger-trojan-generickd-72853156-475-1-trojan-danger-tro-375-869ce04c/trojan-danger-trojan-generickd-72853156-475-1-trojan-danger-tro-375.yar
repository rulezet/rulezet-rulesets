import "pe"
rule _Trojan_Danger_Trojan_GenericKD_72853156_475_1_Trojan_Danger_Tro_375 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72853156_475_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_529_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_53_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea8474f35d3546b8ab8caf16f4cb7bbf46277d08dd0d5c3cbeaf0d02abe6a3f3"
    hash2       = "39326eab10d265c56041bbac42d4955a362bcc040bba5748674728d097b7b648"
    hash3       = "419c3c1d188e41ca981a4ad68a4d1c02000dec30b513b872e89b7732124f3ade"

  strings:
    $s1  = "dLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsacompany is defined as a user able to initiate, or host, a web conference and also " ascii
    $s2  = "dLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsacompany is defined as a user able to initiate, or host, a web conference and also " ascii
    $s3  = "dLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsaanother computer or user. You may transfer the software directly to a third party " ascii
    $s4  = "dLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsaanother computer or user. You may transfer the software directly to a third party " ascii
    $s5  = "may embed fonts in content only as permitted by the embedding restrictions in the fonts.bWI1lzsuCvC1MKxzsuCvC1MKxzsuCvC1MKxzsuCv" ascii
    $s6  = "may embed fonts in content only as permitted by the embedding restrictions in the fonts.bWI1lzsuCvC1MKxzsuCvC1MKxzsuCvC1MKxzsuCv" ascii
    $s7  = "s consulting servicesKF93ZdHeIjKF93ZdHeIjKF93ZdHeIjKF93ZdHeIjKF93ZdHeIj7LJsPWbLHf7LJsPWbLHf7LJsPWbLHf7LJsPWbLHf7LJsPWbLHf15qs8iW" ascii
    $s8  = "dLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsaactivation is meant to identify unauthorized changes to the licensing or activatio" ascii
    $s9  = "s consulting servicesKF93ZdHeIjKF93ZdHeIjKF93ZdHeIjKF93ZdHeIjKF93ZdHeIj7LJsPWbLHf7LJsPWbLHf7LJsPWbLHf7LJsPWbLHf7LJsPWbLHf15qs8iW" ascii
    $s10 = "dLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsa8rWedLGwsaactivation is meant to identify unauthorized changes to the licensing or activatio" ascii
    $s11 = "relating to this agreement may be brought by either party more than two y" fullword ascii
    $s12 = "only as installed on" fullword ascii
    $s13 = "files and macros to verify the integrity and origin of the file contents. The software retrieves certificatesRK9r8" fullword ascii
    $s14 = "participate in a web conference; all" fullword ascii
    $s15 = "assets, owned or m" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "6781466efed8e4a3a5a4c111b8cde4fa" and (8 of them)
    ) or (all of them)
}