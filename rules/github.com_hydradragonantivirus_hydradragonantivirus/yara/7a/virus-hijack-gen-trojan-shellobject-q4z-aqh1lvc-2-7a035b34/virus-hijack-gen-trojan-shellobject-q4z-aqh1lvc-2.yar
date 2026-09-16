rule Virus_Hijack_Gen_Trojan_ShellObject_q4Z_aqH1LVc_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q4Z@aqH1LVc_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14ce2bd45a946bb2c0536c53a8079bd7cddb0f61c9747ee4fbc68a4a0158e76e"

  strings:
    $s1 = "Mmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}