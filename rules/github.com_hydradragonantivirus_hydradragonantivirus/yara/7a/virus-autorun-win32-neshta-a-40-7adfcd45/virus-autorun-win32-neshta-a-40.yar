rule Virus_Autorun_Win32_Neshta_A_40 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_40.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ae80fe731da057fb208df7e85f734bb1c8430bcdbc8be4978eea5b64dbabc2f"

  strings:
    $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"jabswitch.exe\" version=\"" ascii
    $s2 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"jabswitch.exe\" version=\"" ascii
    $s3 = "OpenJDK Platform 21.0.3" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}