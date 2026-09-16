rule Virus_Hijack_Gen_Trojan_ShellObject_j4Z_aqH1LVc {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j4Z@aqH1LVc.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e815d62c12bc0dc0d8519524c2a10e36a49cc7362d537f7b62c3c0c198390a62"

  strings:
    $s1 = "lmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}