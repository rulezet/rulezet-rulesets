rule Virus_Hijack_Gen_Trojan_ShellObject_GyZ_am0pOwg_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.GyZ@am0pOwg_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a13b33059a90c7951a35fb6f5bc09ca03c916381535a361e51dbc9f4f430fc36"

  strings:
    $s1 = "Office Telemetry Agent" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}