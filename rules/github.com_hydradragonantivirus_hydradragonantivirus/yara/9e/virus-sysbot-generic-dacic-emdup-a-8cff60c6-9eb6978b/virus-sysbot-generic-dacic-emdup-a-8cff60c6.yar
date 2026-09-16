rule Virus_Sysbot_Generic_Dacic_Emdup_A_8CFF60C6 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Generic.Dacic.Emdup.A.8CFF60C6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4b1a9100ed80ff9125703970b55ae7ae0366b70500d071b597322a4fc85b98a"

  strings:
    $s1 = "Copyright @ Microsoft Corporation" fullword wide
    $s2 = "Flicks Training" fullword wide
    $s3 = "Windows SDK Installer" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}