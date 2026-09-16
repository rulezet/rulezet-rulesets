rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_aG7qmhc_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@aG7qmhc_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9989328527d1db04c07c536b6b3eb314ba42e4dd575a2bb8d95a9d49d77ac35"

  strings:
    $s1 = "sAGo \\" fullword ascii
    $s2 = "25>wIdE" fullword ascii
    $s3 = "|$DEdo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}