rule Virus_Hijack_Gen_Trojan_ShellObject_tSZ_amMcCQb {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.tSZ@amMcCQb.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "311697087c24decf2bd2fca26b877ad2942e69bc8da9470f0f09ec640d8faf5a"

  strings:
    $s1 = "HGwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}