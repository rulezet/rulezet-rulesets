rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd7d786f6ffe4622aad7f8f7bba9de05c09cf37ed9a4c21a398e92808bd13d35"

  strings:
    $s1 = "<Module>{87EB7557-EBF3-4B21-94E5-575E47AE5A17}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}