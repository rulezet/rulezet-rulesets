rule Trojan_Danger_Trojan_GenericKD_72677122_268_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_268_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ab6214d39dce1dd2583948876b901634ff183c32fa8b14ce254025a40f186a5"

  strings:
    $s1  = "  --set-requested-execution-level <level>    Pass nothing to see usage" fullword ascii
    $s2  = "  --get-version-string <key>                 Print version string" fullword ascii
    $s3  = "<!--Padding to make filesize even multiple of 4 X -->" fullword wide
    $s4  = "Unable to get version string" fullword ascii
    $s5  = "Unable to set execution level" fullword ascii
    $s6  = "  --get-resource-string <key>                Get resource string" fullword ascii
    $s7  = "You should specify a exe/dll file" fullword ascii
    $s8  = "Unable to get resource string" fullword ascii
    $s9  = "  --set-version-string <key> <value>         Set version string" fullword ascii
    $s10 = "Reserved header is not 0 or image type is not icon for '%ls'" fullword wide
    $s11 = "Cannot read icon header for '%ls'" fullword wide
    $s12 = "Unable to change FileVersion string" fullword ascii
    $s13 = "Unable to change file version" fullword ascii
    $s14 = "--set-product-version requires a version string" fullword ascii
    $s15 = "Unable to commit changes" fullword ascii
    $s16 = "--set-file-version requires a version string" fullword ascii
    $s17 = "Unable to parse version string for ProductVersion" fullword ascii
    $s18 = "Unable to change version string" fullword ascii
    $s19 = "--set-resource-string requires int 'Key' and string 'Value'" fullword ascii
    $s20 = "Unable to parse version string for FileVersion" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}