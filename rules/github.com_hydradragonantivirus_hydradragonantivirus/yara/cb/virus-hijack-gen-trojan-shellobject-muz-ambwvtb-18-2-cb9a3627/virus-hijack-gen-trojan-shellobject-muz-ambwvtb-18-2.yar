rule Virus_Hijack_Gen_Trojan_ShellObject_muZ_amBwvTb_18_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_18_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "836604b6cc47521e3e073fac2797c6ef547b91099b0256791c166f6def670c50"

  strings:
    $s1 = "furY? " fullword ascii
    $s2 = "kObI}Q" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}