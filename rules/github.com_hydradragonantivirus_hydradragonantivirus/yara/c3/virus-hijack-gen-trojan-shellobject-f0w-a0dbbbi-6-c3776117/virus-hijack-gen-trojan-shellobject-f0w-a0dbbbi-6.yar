rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c07ed122b2e327de217eecc080516317cde07baa84f4d85b63f99b0d77172ec"

  strings:
    $s1 = "access to the Oracle iSupport program may not be licensed as Employee Users, but must be licensed as `" fullword ascii
    $s2 = "Bdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}