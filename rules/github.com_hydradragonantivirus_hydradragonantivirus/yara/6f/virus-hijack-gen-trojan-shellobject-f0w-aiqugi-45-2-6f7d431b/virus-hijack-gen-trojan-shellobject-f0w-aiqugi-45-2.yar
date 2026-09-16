rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_45_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_45_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "108434385f2de510662517cae3b9063a6b0158c7ef9890ea27433124680d72d2"

  strings:
    $s1 = ".]hUSS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}