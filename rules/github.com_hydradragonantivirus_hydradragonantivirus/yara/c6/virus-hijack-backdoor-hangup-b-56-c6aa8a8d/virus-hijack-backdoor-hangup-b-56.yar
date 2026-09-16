rule Virus_Hijack_Backdoor_Hangup_B_56 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_56.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b95dc9b032ad9c7ef849cfe4baf200299bd0982ce35958b4e07bf1fe54a2b271"

  strings:
    $s1 = "*Trade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}