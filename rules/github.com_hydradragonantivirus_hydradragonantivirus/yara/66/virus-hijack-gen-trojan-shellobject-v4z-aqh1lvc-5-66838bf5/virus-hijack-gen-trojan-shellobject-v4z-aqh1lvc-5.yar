rule Virus_Hijack_Gen_Trojan_ShellObject_v4Z_aqH1LVc_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.v4Z@aqH1LVc_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72ca0010dcd6324ca5d3c7593d8ad051bac2491564b0ed1ed18cbee88edd04ad"

  strings:
    $s1 = "omust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}