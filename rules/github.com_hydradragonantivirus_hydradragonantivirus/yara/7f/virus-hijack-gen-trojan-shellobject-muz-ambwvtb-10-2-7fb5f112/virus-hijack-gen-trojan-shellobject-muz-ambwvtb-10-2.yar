rule Virus_Hijack_Gen_Trojan_ShellObject_muZ_amBwvTb_10_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_10_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1def68e0e089f587a20b6b096ca2bc7d4ba98dbca43ebb05bd5d619ae4846bff"

  strings:
    $s1 = "BALI:'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}