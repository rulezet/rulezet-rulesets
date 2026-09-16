rule Virus_Autorun_Worm_FakeDoc_12 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Worm.FakeDoc_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b7e2502cddd23564dd2819c3ee05594300e51950d00ee0a05dc6591b2cc10cf"

  strings:
    $s1  = "uni043C)/Descent -360/Flags 34/FontBBox[-319 -360 1684 1024]/FontFamily(Minion Pro)/FontFile3 617 0 R/FontName/KGESAY+MinionPro-" ascii
    $s2  = "<</BitsPerComponent 8/ColorSpace/DeviceGray/Filter/DCTDecode/Height 372/Intent/RelativeColorimetric/Length 81260/Name/X/Subtype/" ascii
    $s3  = "<</MarkInfo<</Marked true>>/Metadata 8 0 R/Pages 7 0 R/StructTreeRoot 10 0 R/Type/Catalog/ViewerPreferences<</Direction/L2R>>>>" fullword ascii
    $s4  = "uni043C)/Descent -360/Flags 34/FontBBox[-319 -360 1684 1024]/FontFamily(Minion Pro)/FontFile3 617 0 R/FontName/KGESAY+MinionPro-" ascii
    $s5  = "<</Filter/FlateDecode/Length 374>>stream" fullword ascii
    $s6  = "<</Filter/FlateDecode/Length 12364>>stream" fullword ascii
    $s7  = "<</Extends 1 0 R/Filter/FlateDecode/First 580/Length 1583/N 66/Type/ObjStm>>stream" fullword ascii
    $s8  = "<</Filter/FlateDecode/Length 12495>>stream" fullword ascii
    $s9  = "<</Filter/FlateDecode/Length 12958>>stream" fullword ascii
    $s10 = "<</Filter/FlateDecode/Length 5534/Subtype/Type1C>>stream" fullword ascii
    $s11 = "<</Filter/FlateDecode/Length 6467>>stream" fullword ascii
    $s12 = "<</Extends 1 0 R/Filter/FlateDecode/First 874/Length 818/N 100/Type/ObjStm>>stream" fullword ascii
    $s13 = "<</Filter/FlateDecode/Length 283>>stream" fullword ascii
    $s14 = "<</Extends 1 0 R/Filter/FlateDecode/First 876/Length 847/N 100/Type/ObjStm>>stream" fullword ascii
    $s15 = "<</Filter/FlateDecode/Length 534>>stream" fullword ascii
    $s16 = "<</Filter/FlateDecode/Length 6738>>stream" fullword ascii
    $s17 = "<</Extends 1 0 R/Filter/FlateDecode/First 877/Length 870/N 100/Type/ObjStm>>stream" fullword ascii
    $s18 = "<</Filter/FlateDecode/Length 5336>>stream" fullword ascii
    $s19 = "<</Filter/FlateDecode/Length 3536/Subtype/Type1C>>stream" fullword ascii
    $s20 = "<</Filter/FlateDecode/Length 1254/Subtype/Type1C>>stream" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}