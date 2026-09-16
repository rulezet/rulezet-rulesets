rule _Trojan_Hooker_Win32_Floxif_A_50_Virus_Hijack_Gen_Trojan_ShellOb_289 {
  meta:
    description = "datamaliciousorder - from files Trojan.Hooker_Win32.Floxif.A_50.vir, Virus.Hijack_Gen.Trojan.ShellObject.k8Z@au4JtZd_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4684ff24fbb5cc8676ff2875834c4bc3fe8e14451d850e61e7e5a4cee68a488"
    hash2       = "2214fb9929e8215d9abf46c3317fe3c7517d86e750b395f0831f6f6c02a2dc0d"

  strings:
    $s1 = "Password for \"%s\"" fullword wide
    $s2 = "Overwrite file \"%s\" with \"%s\"" fullword wide
    $s3 = "Please insert a blank disk #%d" fullword wide
    $s4 = "Please insert the first disk" fullword wide
    $s5 = "Please insert the last disk" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}