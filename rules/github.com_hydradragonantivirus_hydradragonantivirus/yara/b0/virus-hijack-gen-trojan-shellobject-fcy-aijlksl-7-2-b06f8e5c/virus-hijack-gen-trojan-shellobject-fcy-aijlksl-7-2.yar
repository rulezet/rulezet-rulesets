rule Virus_Hijack_Gen_Trojan_ShellObject_fCY_aijlKSl_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6f4452979012b1d82a6b5c045a442da51e67f03476a51abe9c17de6ccc68e52"

  strings:
    $s1 = ".?AV?$scope_guard_func_impl@V?$_Bind@$0A@XP6GHPBX@ZAAPAX@std@@@utility@appv@@" fullword ascii
    $s2 = ".?AV?$scope_guard_func_impl@V?$_Bind@$0A@XP6GJPAPAG@ZPAPAG@std@@@utility@appv@@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}