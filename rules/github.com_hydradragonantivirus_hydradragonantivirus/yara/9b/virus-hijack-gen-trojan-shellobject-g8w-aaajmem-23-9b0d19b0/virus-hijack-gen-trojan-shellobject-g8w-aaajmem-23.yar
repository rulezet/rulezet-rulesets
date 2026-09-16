rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_23 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_23.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46df03f166ad98827d551a4c34efcb805492b8a8c69ba79c6ac09c2c966bef02"

  strings:
    $s1 = "v?What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}