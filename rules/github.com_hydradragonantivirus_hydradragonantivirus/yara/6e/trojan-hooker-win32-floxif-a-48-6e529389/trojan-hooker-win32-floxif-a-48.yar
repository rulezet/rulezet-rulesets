rule Trojan_Hooker_Win32_Floxif_A_48 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_48.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce9adf2be6a401b0e51308cf0e06a9bc10df793520998fab606d0ca10f891efe"

  strings:
    $s1 = "<!--The ID below indicates application support for Windows 10 -->" fullword ascii
    $s2 = "opera?" fullword ascii
    $s3 = ":known ex" fullword ascii
    $s4 = ">ds coLp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}