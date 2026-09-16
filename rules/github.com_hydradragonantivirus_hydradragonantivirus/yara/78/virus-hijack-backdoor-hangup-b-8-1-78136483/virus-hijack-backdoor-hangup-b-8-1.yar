rule Virus_Hijack_Backdoor_Hangup_B_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e52d42d929843d7924f6c5d35fc9a707e6d725134b15fc88461eaa211efa924"

  strings:
    $s1 = "PHYSICAL;DR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}