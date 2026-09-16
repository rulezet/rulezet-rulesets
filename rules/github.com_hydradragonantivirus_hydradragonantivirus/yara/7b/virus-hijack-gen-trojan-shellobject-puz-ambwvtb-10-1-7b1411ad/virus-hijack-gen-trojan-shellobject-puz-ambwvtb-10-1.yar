rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9bd07bcfe6f4a7ebe2278727efa47cb2b556129b99851294a5727fed1ecbbe27"

  strings:
    $s1 = "asSe}C" fullword ascii
    $s2 = "%>Naid" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}