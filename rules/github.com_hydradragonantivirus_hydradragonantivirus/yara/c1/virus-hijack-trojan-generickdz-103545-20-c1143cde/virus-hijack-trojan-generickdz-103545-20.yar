rule Virus_Hijack_Trojan_GenericKDZ_103545_20 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_20.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "738b062c9ca5c4bba3c3077d325fd872ab0f428206abb9f4195d812187cc7027"

  strings:
    $s1 = "www.oracle.com/education/oln/index.html, and may be updated by Oracle from time to time with`" fullword ascii
    $s2 = "Jsoftware features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}