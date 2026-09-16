rule Virus_Hijack_Generic_Dacic_76A3436A_A_FA2A2EAE {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Generic.Dacic.76A3436A.A.FA2A2EAE.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "629b3584810d780d2e436e6563794a4faf0d2ad2b2b6846f5f5ca7e1212ac216"

  strings:
    $s1 = "HKCU\\Software\\Microsoft\\Internet Explorer\\Main\\Start Page" fullword wide
    $s2 = "echo Y| cacls " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}