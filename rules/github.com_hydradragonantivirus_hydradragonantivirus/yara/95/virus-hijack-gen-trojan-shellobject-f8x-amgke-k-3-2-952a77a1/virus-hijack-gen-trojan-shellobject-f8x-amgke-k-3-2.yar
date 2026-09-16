rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_amgke_k_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@amgke!k_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c53b754673d79a9d733088eb25e792128393821974bac4339228bbf4791d8bef"

  strings:
    $s1 = ".?AV?$scope_guard_func_impl@V?$_Bind@$0A@XP6GHPBX@ZAAPAX@std@@@utility@appv@@" fullword ascii
    $s2 = ".?AV?$scope_guard_func_impl@V?$_Bind@$0A@XP6GJPAPAG@ZPAPAG@std@@@utility@appv@@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}