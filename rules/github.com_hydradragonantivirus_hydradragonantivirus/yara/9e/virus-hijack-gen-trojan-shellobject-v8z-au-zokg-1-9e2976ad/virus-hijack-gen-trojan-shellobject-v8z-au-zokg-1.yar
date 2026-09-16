rule Virus_Hijack_Gen_Trojan_ShellObject_v8Z_au_Zokg_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.v8Z@au@Zokg_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc889d5788153bb26fc428c986c2717c5525c558352032016df0c41574021285"

  strings:
    $s1 = "hUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}