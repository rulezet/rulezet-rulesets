rule Trojan_Danger_Trojan_GenericKD_72677122_267_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_267_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76413a804107edf89443391767e152cbfca49ec48900c407fdaf9e307a3f567e"

  strings:
    $s1  = "LUMtarget Version %s -- %s Target ID Tool" fullword ascii
    $s2  = "*** Warning: LUMtarget could not generate secure ID" fullword ascii
    $s3  = "Command line usage:  LUMtarget" fullword ascii
    $s4  = "Open Process Token failed: %d" fullword ascii
    $s5  = "Open Process failed: %d" fullword ascii
    $s6  = "US Government Users Restricted Rights - Use, duplication or disclosure" fullword ascii
    $s7  = " password: %s" fullword ascii
    $s8  = "Get Token Information failed: %d" fullword ascii
    $s9  = "get_winnt_node_id: \"LUMDRIVER\" key value found. Driver is" fullword wide
    $s10 = "GetHwMac: Media Connection Status" fullword ascii
    $s11 = "-usage\" to get usage" fullword ascii
    $s12 = "Invalid target type for this vendor" fullword ascii
    $s13 = "Wrong target" fullword ascii
    $s14 = "Unable to obtain target." fullword ascii
    $s15 = "Unable to obtain target vector." fullword ascii
    $s16 = "Open Target" fullword ascii
    $s17 = "%s: %s is version %d, we need %d." fullword ascii
    $s18 = "Media Connection Status Unknown. DeviceIoControl failed" fullword ascii
    $s19 = "   [-d] (set manually device driver name for target id)" fullword ascii
    $s20 = "malloc token groups failed" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}