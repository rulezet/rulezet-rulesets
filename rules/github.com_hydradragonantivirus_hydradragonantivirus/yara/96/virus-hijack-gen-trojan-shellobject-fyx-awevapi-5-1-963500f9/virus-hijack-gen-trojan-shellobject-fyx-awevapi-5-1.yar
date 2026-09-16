rule Virus_Hijack_Gen_Trojan_ShellObject_fyX_aWevApi_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyX@aWevApi_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86703029c7fba804615484094f9b04b7300aec433fd0ba7eed618c59076b6154"

  strings:
    $s1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security>    <requestedPrivileges>     <requestedExecutionLevel  level=\"" ascii
    $s3 = "ardly thought of it since then - that he had a charm" fullword wide
    $s4 = "think probably it was quite an attractive" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}