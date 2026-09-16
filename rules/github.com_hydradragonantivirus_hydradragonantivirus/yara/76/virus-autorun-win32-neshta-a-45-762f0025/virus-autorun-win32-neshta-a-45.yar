rule Virus_Autorun_Win32_Neshta_A_45 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_45.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec37586ae12116b2d01b2ba686c27e87fb026229d5adc86019e7032a80efc0bb"

  strings:
    $s1  = "Skipping non-XML file: {0} - reason: {1}" fullword wide
    $s2  = "shine.exe scans directories, .wixproj files and .wixpdbs for WiX items such as:" fullword wide
    $s3  = "Unknown command line parameter: {0}" fullword wide
    $s4  = " <description>WiX Toolset Scanner</description> " fullword ascii
    $s5  = "Displaying graph to console is not supported yet. Use the -dgml switch." fullword wide
    $s6  = " usage: shine.exe [options] path|*.wixproj|*.wixpdb|..." fullword wide
    $s7  = "   -dgmlTemplate file       a valid DGML file populated with data from scan" fullword wide
    $s8  = "Features, ComponentGroups, Components and the references between them." fullword wide
    $s9  = "wix:Feature|wix:FeatureRef|wix:ComponentGroupRef|wix:ComponentRef|wix:Component" fullword wide
    $s10 = "wix:ComponentGroupRef|wix:ComponentRef|wix:Component" fullword wide
    $s11 = "                              proj - project files" fullword wide
    $s12 = "                              file - source files" fullword wide
    $s13 = "                              ref  - symbol references" fullword wide
    $s14 = "                              all  - all of the above [default]" fullword wide
    $s15 = "WiX Toolset Scanner" fullword wide
    $s16 = "   -dgml file               save scan as DGML file" fullword wide
    $s17 = "   -excludeSymbol symbol    remove symbol and symbols it references from scan" fullword wide
    $s18 = "   -includeSymbol symbol    filter scan to include only specified symbol(s)" fullword wide
    $s19 = "   -show proj;file;sym;ref  displays only the specified items in the scan" fullword wide
    $s20 = "   -? | -help             this help information" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}