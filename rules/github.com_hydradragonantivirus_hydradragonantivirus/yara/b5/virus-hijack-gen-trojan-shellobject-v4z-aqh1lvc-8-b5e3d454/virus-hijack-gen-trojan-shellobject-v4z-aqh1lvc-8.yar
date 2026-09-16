rule Virus_Hijack_Gen_Trojan_ShellObject_v4Z_aqH1LVc_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.v4Z@aqH1LVc_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c40eff56ab1bfc0cc4466951c65f515fbf3ca8d365493c370cad448856b71d48"

  strings:
    $s1 = "mmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}