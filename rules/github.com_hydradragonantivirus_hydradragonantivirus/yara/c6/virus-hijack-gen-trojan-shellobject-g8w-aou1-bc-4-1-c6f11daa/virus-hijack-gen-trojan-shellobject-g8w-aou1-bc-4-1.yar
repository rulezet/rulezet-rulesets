rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aOU1_bc_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aOU1!bc_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e21b9f660cbfb7b194aa10bbf47d939224808fc0e2dd95a497b46739fbf8efd8"

  strings:
    $s1 = "<generated method>)" fullword ascii
    $s2 = "NanoCore Client" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}