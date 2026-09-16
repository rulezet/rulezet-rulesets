rule Virus_Autorun_Win32_Nestha_C_2 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Nestha.C_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "597dba49e38a3600634715a9e6a11dc64c0dd2cd1fed8383203eb4d8bf6ecd3a"

  strings:
    $s1  = "does not equal the target version " fullword ascii
    $s2  = "Failed to get packages with family name. " fullword ascii
    $s3  = "Failed to get packages the first package in family_packages." fullword ascii
    $s4  = "Failed to grant access to path: " fullword ascii
    $s5  = "Failed to impersonate user." fullword ascii
    $s6  = "There is no active user to impersonate. Set Copilot ACLs through provisioned packages." fullword ascii
    $s7  = "Could not get the package full name: " fullword ascii
    $s8  = "Couldn't get program data path." fullword ascii
    $s9  = "Could not get the current package: " fullword ascii
    $s10 = "Could not get the package id: " fullword ascii
    $s11 = "The version from the installed package is not valid." fullword ascii
    $s12 = "The current version " fullword ascii
    $s13 = "Failed to create IPackageManager." fullword ascii
    $s14 = "Copilot com path: " fullword ascii
    $s15 = "d: Alignment assumption is violated" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}