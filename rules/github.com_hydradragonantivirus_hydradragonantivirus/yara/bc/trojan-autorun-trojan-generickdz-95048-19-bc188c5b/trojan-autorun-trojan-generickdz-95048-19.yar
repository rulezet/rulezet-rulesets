rule Trojan_Autorun_Trojan_GenericKDZ_95048_19 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.95048_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a70aa35822821cfe3765521c177c921ffd0ff9dd88a0438d9a964032e91ce0dd"

  strings:
    $s1 = "ecfi937<g<g7A;?DoDo?ICGLwLwGQKOT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}