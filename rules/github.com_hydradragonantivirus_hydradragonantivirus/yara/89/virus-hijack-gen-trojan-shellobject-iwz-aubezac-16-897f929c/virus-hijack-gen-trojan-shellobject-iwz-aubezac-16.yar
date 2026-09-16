rule Virus_Hijack_Gen_Trojan_ShellObject_iWZ_auBEZAc_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iWZ@auBEZAc_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "431e278bbca73da2b0d76219fb6d32985b60506082b9541d7a4cbb8f448e9d61"

  strings:
    $s1 = "<automatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}