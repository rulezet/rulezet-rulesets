rule _Trojan_Danger_Trojan_GenericKD_46147426_Virus_Hijack_Trojan_Gen_224 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.46147426.vir, Virus.Hijack_Trojan.GenericKDZ.105924_190_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51cf85f0909adb4c6b6473126e86916877768b1a1233cca35c189529e226cb43"
    hash2       = "218c3d757fba40a487f951ccfb71e651996f0baebc8f4fc070773dd385b3233e"

  strings:
    $s1  = "                                 <item id=\"%d\" target=\"%d\">%ws</item> " fullword wide
    $s2  = "                                 <item id=\"%d\" target=\"%d\" enable=\"%d\">%ws</item> " fullword wide
    $s3  = "                                 <item target=\"%d\">%ws</item> " fullword wide
    $s4  = "                             <item id=\"%d\" target=\"%d\">%ws</item>" fullword wide
    $s5  = "                             <item target=\"%d\">%ws</item>" fullword wide
    $s6  = "<description>Windows Media Player Gadget for Windows SideShow capable devices</description>" fullword ascii
    $s7  = "WMP SideShow Gadget" fullword wide
    $s8  = "<body><menu id=\"%d\"> " fullword wide
    $s9  = "             <content id=\"%d\" title=\" \"> " fullword wide
    $s10 = "WMP Auxiliary Display Connector" fullword wide
    $s11 = "Windows Media Player Gadget for Windows SideShow capable devices" fullword wide
    $s12 = "Failed to initialize the WMP Connector [0x%08lx],  exiting..." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}