rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aOGzovi {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aOGzovi.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36de716f64a5f9119d6d123ee22b69413e7ae549e00ea97685b0090552cfa75a"

  strings:
    $s1 = "~\"Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device th" ascii
    $s2 = "~\"Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device th" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}