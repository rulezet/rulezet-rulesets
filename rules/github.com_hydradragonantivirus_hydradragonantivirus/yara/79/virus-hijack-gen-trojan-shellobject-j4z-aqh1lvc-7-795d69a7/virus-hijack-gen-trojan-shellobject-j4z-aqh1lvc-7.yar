rule Virus_Hijack_Gen_Trojan_ShellObject_j4Z_aqH1LVc_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j4Z@aqH1LVc_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "706833a06515a2d9ddd55cbc20bb1ae1ab863578a313c24342e8eb1fab378ffb"

  strings:
    $s1 = "Kmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}