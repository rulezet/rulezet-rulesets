rule Trojan_Autorun_Win32_Neshta_A_6_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Win32.Neshta.A_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d109c45aadfbba8b45f7a75f0d9ce3c9a7e965d1e4665573b8d78854f382b0a"

  strings:
    $s1 = "-|program and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii
    $s2 = "-|program and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viol" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}