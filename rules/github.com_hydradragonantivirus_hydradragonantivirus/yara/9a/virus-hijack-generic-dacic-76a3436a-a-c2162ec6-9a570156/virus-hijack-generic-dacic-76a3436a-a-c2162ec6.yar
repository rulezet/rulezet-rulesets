rule Virus_Hijack_Generic_Dacic_76A3436A_A_C2162EC6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Generic.Dacic.76A3436A.A.C2162EC6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c7258c8adc38d760c695575625602e3770c73a685b70d90fb9730beb904a569"

  strings:
    $s1 = "HKCU\\Software\\Microsoft\\Internet Explorer\\Main\\Start Page" fullword wide
    $s2 = "echo Y| cacls " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}