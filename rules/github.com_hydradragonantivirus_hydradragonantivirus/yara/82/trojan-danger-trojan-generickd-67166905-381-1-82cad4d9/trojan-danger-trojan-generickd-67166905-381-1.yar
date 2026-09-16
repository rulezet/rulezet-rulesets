rule Trojan_Danger_Trojan_GenericKD_67166905_381_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_381_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c7c38d86f633fb4f2e4e818936241587ce067ecd1d53e504a1107c20076299d"

  strings:
    $s1 = "glUE)#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}