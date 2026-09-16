rule Virus_Hijack_Trojan_Agent_DQQO_380 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_380.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39aab699ec55db0431a3fe7af09243b51daa18fdc579a3d0b13198295cb8ce58"

  strings:
    $s1 = ",*Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}