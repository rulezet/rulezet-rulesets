rule Trojan_Autorun_Generic_Dacic_AAD0835C_A_866F9A53_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Generic.Dacic.AAD0835C.A.866F9A53_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbf758df19ce392fa4fab0088429c5734cbc0b89694aba19ab3a55aa1b71a0cd"

  strings:
    $s1 = "Alias attribute is invalid in the profile schema." fullword wide
    $s2 = "Alias attribute value is not unique in the profile." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}