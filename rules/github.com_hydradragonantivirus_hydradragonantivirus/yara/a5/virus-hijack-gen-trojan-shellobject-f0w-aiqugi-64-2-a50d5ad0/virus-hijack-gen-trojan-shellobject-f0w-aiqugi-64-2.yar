rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_64_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_64_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3084dc23a5946107b94a7f4801b3207411b03fff8358bba5eb265a2cda14ac11"

  strings:
    $s1 = "Couldn't remove file spec when attempting to verify the working directory path.  (%d)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}