rule _20160516_7eca96d4c32eae4cd355d16266ca4920_20160516_f50aabb811a7_1173 {
  meta:
    description = "datamaliciousorder - from files 20160516_7eca96d4c32eae4cd355d16266ca4920.js, 20160516_f50aabb811a7d4b39bf3f77bc93029b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a76feada51d3a7cc1c596192bd4bda468666fa23b00f07bb2dc55f76ddf760da"
    hash2       = "7b81352504f658dca17f67479755685e0dc4754ef2b0e613187101702fed20d1"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* H  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* H  */ = 5316 - 5314;" fullword ascii
    $s3  = "CONNECTION /* H  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s4  = "Turkey = /* H  */(/* H  */\"noitisop\").split(''/* H  */).reverse(/* H  */).join('');" fullword ascii
    $s5  = "if (place /* H  */ == 1)" fullword ascii
    $s6  = " var place /* H  */ = 3-2;" fullword ascii
    $s7  = "for (;place /* H  */;){" fullword ascii
    $s8  = "while (place /* H  */) { " fullword ascii
    $s9  = "place0 /* H  */= true;/* H  */" fullword ascii
    $s10 = "place /* H  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}