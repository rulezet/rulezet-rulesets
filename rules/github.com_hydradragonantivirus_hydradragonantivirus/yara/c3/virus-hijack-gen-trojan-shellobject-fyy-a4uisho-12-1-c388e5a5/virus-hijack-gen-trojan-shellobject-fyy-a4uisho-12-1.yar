rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_a4uiSHo_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@a4uiSHo_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93655901e4c8918294fbeb5689c86ce3802534c6ded8dac05a072b93260d5588"

  strings:
    $s1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security>    <requestedPrivileges>     <requestedExecutionLevel  level=\"" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}