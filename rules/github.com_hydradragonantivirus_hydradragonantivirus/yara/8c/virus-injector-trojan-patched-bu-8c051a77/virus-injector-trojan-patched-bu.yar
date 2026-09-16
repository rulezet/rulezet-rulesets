rule Virus_Injector_Trojan_Patched_BU {
  meta:
    description = "datamaliciousorder - file Virus.Injector_Trojan.Patched.BU.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d2ab15b306720b8b2a35f3870d6d50ed066976c71d10d4961abc1fa547b0069"

  strings:
    $s1  = "Failed to process Border" fullword ascii
    $s2  = "Failed to process aperture definition" fullword ascii
    $s3  = "Program processing general failure" fullword ascii
    $s4  = "process %d percent done" fullword ascii
    $s5  = "MIO internal: A fatal error has occurred inside MIO while processing error %d....." fullword ascii
    $s6  = "Getting Comps" fullword ascii
    $s7  = "Failed to read error message %d from catalog" fullword ascii
    $s8  = "MIO ERROR : The given application string is not 1 - %d characters long" fullword ascii
    $s9  = "' Advanced CAM Technologies Bitmap Comparison Log File Version: 1.0" fullword ascii
    $s10 = "MIO ERROR : Message file was compiled with an old compiler version, re-compile with version %d.%d or later" fullword ascii
    $s11 = "%s, line #%d: Error E_%02d detected" fullword ascii
    $s12 = "UNKNOWN - %d" fullword ascii
    $s13 = "Line No %ld - " fullword ascii
    $s14 = "' Compare failed at ( %7.3f : %7.3f )  ( %7.3f : %7.3f )" fullword ascii
    $s15 = "Check pin violations - %s" fullword ascii
    $s16 = "SUBCIRCUIT" fullword ascii
    $s17 = "Form Address :- " fullword ascii
    $s18 = "Getting Copper Hatches" fullword ascii
    $s19 = "MIO ERROR : Error message %d not found in catalog %s" fullword ascii
    $s20 = "Getting Copper Shapes" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}