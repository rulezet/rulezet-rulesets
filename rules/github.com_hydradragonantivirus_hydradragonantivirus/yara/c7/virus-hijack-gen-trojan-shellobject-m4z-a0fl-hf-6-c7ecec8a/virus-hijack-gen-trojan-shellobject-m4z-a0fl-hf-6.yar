rule Virus_Hijack_Gen_Trojan_ShellObject_m4Z_a0fL_hf_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m4Z@a0fL!hf_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04ee26790620b732d10dfaf23c185b32ec28a41117e9fe3db436535feb91c5e3"

  strings:
    $s1 = "BReW}a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}