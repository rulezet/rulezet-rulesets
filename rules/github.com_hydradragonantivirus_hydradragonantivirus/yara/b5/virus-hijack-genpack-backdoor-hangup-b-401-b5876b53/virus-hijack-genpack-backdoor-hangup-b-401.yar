rule Virus_Hijack_GenPack_Backdoor_Hangup_B_401 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_401.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8855ca92e89d74b8332a89d0be03188411dcdde0abaa10390be8d0ff986662c1"

  strings:
    $s1 = ".and hardware systems to the applications programs and (c) building extensions to applications programs. You shall not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}