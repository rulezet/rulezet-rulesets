rule Virus_Hijack_Gen_Trojan_ShellObject_r8W_au4YcDk_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.r8W@au4YcDk_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "361d06ede32f653dd8d66b4c12de5f722ae558c2e016df09bf3272f23c6805bb"

  strings:
    $s1 = "FAILED TO EXECUTE  " fullword ascii
    $s2 = "Bits index out of range/Menu '%s' is already being used by another form*Windows socket error: %s (%d), on API '%s'" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}