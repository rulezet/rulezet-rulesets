rule _20160516_03362bf1df8e40f9f2bbd783b0dff45b_20160516_4efe71c60b9e_1145 {
  meta:
    description = "datamaliciousorder - from files 20160516_03362bf1df8e40f9f2bbd783b0dff45b.js, 20160516_4efe71c60b9e69a45804114d9818078c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f8dd8f0ed790f36d147704e6b72411da44dd73e29ef77e2539afe2c3818c4ec"
    hash2       = "b3299dd293cfef3a1b86c11029cb5e1b419083974dd34bce640b46d171bc38b0"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* k  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* k  */ = 5316 - 5314;" fullword ascii
    $s3  = "Turkey = /* k  */(/* k  */\"noitisop\").split(''/* k  */).reverse(/* k  */).join('');" fullword ascii
    $s4  = "CONNECTION /* k  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s5  = "for (;place /* k  */;){" fullword ascii
    $s6  = "place0 /* k  */= true;/* k  */" fullword ascii
    $s7  = "if (place /* k  */ == 1)" fullword ascii
    $s8  = "while (place /* k  */) { " fullword ascii
    $s9  = " var place /* k  */ = 3-2;" fullword ascii
    $s10 = "place /* k  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}