rule Virus_Hijack_Gen_Trojan_ShellObject_v4Z_aqH1LVc_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.v4Z@aqH1LVc_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acc03f0c19ae8a71c6d946c7c63356077a3f0191b58898940bbad22d86ccd877"

  strings:
    $s1 = "xmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}