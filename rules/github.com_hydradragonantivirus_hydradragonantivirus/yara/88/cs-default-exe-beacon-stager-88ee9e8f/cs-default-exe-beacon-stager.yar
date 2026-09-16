import "pe"
rule CS_default_exe_beacon_stager {
  meta:
    description = "Remote CS beacon execution as a service - spoolsv.exe"
    author      = "TheDFIRReport"
    date        = "2021-07-13"
    hash1       = "f3dfe25f02838a45eba8a683807f7d5790ccc32186d470a5959096d009cc78a2"

  strings:
    $s1 = "windir" fullword ascii
    $s2 = "rundll32.exe" fullword ascii
    $s3 = "VirtualQuery failed for %d bytes at address %p" fullword ascii
    $s4 = "msvcrt.dll" fullword wide

  condition:
    uint16(0) == 0x5a4d and filesize < 800KB and (pe.imphash() == "93f7b1a7b8b61bde6ac74d26f1f52e8d" and
      3 of them) or (all of them)
}