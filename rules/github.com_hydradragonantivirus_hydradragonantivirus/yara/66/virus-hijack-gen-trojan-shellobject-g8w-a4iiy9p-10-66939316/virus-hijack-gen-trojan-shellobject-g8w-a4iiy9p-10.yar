rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_a4IIY9p_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@a4IIY9p_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c8eec1d961045308c2d3946732afb209078582ff23cf5fa24345d71f28b3984"

  strings:
    $s1 = "tSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}