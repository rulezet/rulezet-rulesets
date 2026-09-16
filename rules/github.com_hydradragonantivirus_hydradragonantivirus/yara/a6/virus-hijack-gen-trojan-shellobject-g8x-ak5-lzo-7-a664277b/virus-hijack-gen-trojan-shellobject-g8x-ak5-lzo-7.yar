rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15fd85326b3bb700b1b09121114e451c057a806ca49fa975f63d4e531b1f6ddf"

  strings:
    $s1 = ">jUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}