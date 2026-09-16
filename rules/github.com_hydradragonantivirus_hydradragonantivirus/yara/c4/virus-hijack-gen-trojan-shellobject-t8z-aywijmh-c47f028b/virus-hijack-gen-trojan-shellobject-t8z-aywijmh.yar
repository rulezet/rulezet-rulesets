rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_ayWIjmh {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@ayWIjmh.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12c0343f4a0ea65168498e60031520c99ee4a4d0fdc3e658084976c22781a673"

  strings:
    $s1 = "MeNd)]&w" fullword ascii
    $s2 = "Fyour order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}