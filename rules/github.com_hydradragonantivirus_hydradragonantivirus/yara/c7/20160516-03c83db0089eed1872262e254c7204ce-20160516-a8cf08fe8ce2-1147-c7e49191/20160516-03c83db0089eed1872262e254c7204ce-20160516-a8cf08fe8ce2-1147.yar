rule _20160516_03c83db0089eed1872262e254c7204ce_20160516_a8cf08fe8ce2_1147 {
  meta:
    description = "datamaliciousorder - from files 20160516_03c83db0089eed1872262e254c7204ce.js, 20160516_a8cf08fe8ce2ff7fd168235fb60919ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9f86acd4ab25d0f485daf36a8ca8b75542b976209565a3f21f6b72702174a5c"
    hash2       = "eeafa2e77361f4c38c2595ecb63caa8f87707c540b738ea2cf57453e74841751"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* Y  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* Y  */ = 5316 - 5314;" fullword ascii
    $s3  = "Turkey = /* Y  */(/* Y  */\"noitisop\").split(''/* Y  */).reverse(/* Y  */).join('');" fullword ascii
    $s4  = "CONNECTION /* Y  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s5  = "if (place /* Y  */ == 1)" fullword ascii
    $s6  = "place0 /* Y  */= true;/* Y  */" fullword ascii
    $s7  = " var place /* Y  */ = 3-2;" fullword ascii
    $s8  = "while (place /* Y  */) { " fullword ascii
    $s9  = "for (;place /* Y  */;){" fullword ascii
    $s10 = "place /* Y  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}