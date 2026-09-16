rule Virus_Danger_Trojan_GenericKDZ_103285_46 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.GenericKDZ.103285_46.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a7eb7912a747198288690b75d9392e9def632a86df1a5e5eee2c08861f5b76e"

  strings:
    $s1 = "Pa neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii
    $s2 = "mUsk;-Tk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}