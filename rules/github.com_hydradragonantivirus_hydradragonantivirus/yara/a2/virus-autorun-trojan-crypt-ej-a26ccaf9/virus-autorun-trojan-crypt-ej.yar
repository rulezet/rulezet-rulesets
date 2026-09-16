rule Virus_Autorun_Trojan_Crypt_EJ {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Trojan.Crypt.EJ.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "673938f5fa28ee6a76edbd252ba0d2b0e2457c15d153debf40d9ab6c040b198a"

  strings:
    $s1 = "u#Hand" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}