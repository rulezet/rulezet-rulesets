rule Virus_Sysbot_Trojan_GenericKD_71671752_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2eab1b278dad51aa839fa039a65243972ad0f734843ab81cc0140d7fd763842"

  strings:
    $s1 = "smur@\"" fullword ascii
    $s2 = "#MAuX!-" fullword ascii
    $s3 = "DeAn>T" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}