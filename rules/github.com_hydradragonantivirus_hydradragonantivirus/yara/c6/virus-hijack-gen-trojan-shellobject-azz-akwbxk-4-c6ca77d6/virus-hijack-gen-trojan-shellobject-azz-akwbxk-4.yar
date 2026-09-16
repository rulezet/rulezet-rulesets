rule Virus_Hijack_Gen_Trojan_ShellObject_azZ_aKwbXk_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.azZ@aKwbXk_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3167028d225fb153d3b24c77b6a55beba23bf79487d88fbb1c0c4c3fc6912e1"

  strings:
    $s1 = "vCallbackListToRpc: begin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}