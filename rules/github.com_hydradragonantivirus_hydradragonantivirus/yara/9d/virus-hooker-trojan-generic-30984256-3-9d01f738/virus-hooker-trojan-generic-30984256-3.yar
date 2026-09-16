rule Virus_Hooker_Trojan_Generic_30984256_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Trojan.Generic.30984256_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "928977664a67ad0ff4e57a848d98bd35f2dabbf2d98944f0e075097e740712b4"

  strings:
    $s1 = "|\\(WheT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}