rule _20160516_74206bc09a5ddb7fc68a9dae7b65a729_20160516_ed6c73a0ad36_1170 {
  meta:
    description = "datamaliciousorder - from files 20160516_74206bc09a5ddb7fc68a9dae7b65a729.js, 20160516_ed6c73a0ad366a081d253f5dfb1f3328.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f829860024cbab00f01040117597695e79079eb4d9fd6e172556a7450350058"
    hash2       = "4fcaa44e92b19a179906ca14b169518ff7b96338e3a15b68e3040fc67e64a3f7"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* K  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* K  */ = 5316 - 5314;" fullword ascii
    $s3  = "CONNECTION /* K  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s4  = "Turkey = /* K  */(/* K  */\"noitisop\").split(''/* K  */).reverse(/* K  */).join('');" fullword ascii
    $s5  = "place0 /* K  */= true;/* K  */" fullword ascii
    $s6  = "if (place /* K  */ == 1)" fullword ascii
    $s7  = "while (place /* K  */) { " fullword ascii
    $s8  = " var place /* K  */ = 3-2;" fullword ascii
    $s9  = "for (;place /* K  */;){" fullword ascii
    $s10 = "place /* K  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}