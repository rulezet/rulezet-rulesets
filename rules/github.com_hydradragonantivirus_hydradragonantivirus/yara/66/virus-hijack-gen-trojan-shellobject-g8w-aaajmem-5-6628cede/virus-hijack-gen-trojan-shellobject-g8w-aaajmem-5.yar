rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db1a19db3047cb31d5708828ec7a7d8e9a510a391f509ba6054382b504c62f37"

  strings:
    $s1 = "w#What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}