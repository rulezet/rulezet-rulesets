rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aOU1_bc_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aOU1!bc_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ed8c3e2b57e9644b074fcda195f49b7f604c87350ac1739b91548c08146bf6e"

  strings:
    $s1 = "<generated method>)" fullword ascii
    $s2 = "NanoCore Client" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}