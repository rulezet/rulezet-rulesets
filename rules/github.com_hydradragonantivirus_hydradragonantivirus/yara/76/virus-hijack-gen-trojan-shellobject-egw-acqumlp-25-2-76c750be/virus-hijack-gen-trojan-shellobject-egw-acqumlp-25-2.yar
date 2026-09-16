rule Virus_Hijack_Gen_Trojan_ShellObject_eGW_aCQuMlp_25_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eGW@aCQuMlp_25_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a13c79aea78e9f0c94d8100ee6cc12f454d44851d45a78706dc4b356afacc6b"

  strings:
    $s1 = "new COYOTE TRIXER.exe" fullword wide
    $s2 = "\\SystemVolume\\new COYOTE TRIXER" fullword wide
    $s3 = "new COYOTE TRIXER" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}