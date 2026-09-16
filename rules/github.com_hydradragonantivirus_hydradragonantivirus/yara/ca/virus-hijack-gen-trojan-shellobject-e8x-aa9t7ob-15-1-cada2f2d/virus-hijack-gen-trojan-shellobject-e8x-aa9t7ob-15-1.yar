rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "def80f5379a616c7985d76932c65e4d35b53287eba6ad964a08a3e9d589be0bf"

  strings:
    $s1 = "Task Manager.exe" fullword wide
    $s2 = "Unable to change value to false while a transparent BackColor is in use." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}