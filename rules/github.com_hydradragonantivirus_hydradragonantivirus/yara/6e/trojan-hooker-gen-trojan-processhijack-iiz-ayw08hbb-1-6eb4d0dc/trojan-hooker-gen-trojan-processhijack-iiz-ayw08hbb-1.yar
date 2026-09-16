rule Trojan_Hooker_Gen_Trojan_ProcessHijack_iIZ_ayW08hbb_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Gen.Trojan.ProcessHijack.iIZ@ayW08hbb_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ec965bdfa2efe93d1e6cc332e094c70225e011675c27f5adefad4065270514f"

  strings:
    $s1 = "SECURE APPLICATION DEVELOPMENT1)0'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}