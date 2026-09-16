rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKzODno_17_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68bf6431df2e54fd6bd85a61554650bd8132f0226c6bb1be97a30b3ff9149171"

  strings:
    $s1 = "><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker" ascii
    $s2 = " <?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersi" ascii
    $s3 = "performs complex" fullword ascii
    $s4 = " <?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersi" ascii
    $s5 = "s\"Destroy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}