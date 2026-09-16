rule Virus_Hijack_Gen_Trojan_ShellObject_C8Z_amCvSwc_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.C8Z@amCvSwc_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09b8ff35773afa657c2836a5ed694ddac52a9b566456850475415c68b6a956c9"

  strings:
    $s1 = "cUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}