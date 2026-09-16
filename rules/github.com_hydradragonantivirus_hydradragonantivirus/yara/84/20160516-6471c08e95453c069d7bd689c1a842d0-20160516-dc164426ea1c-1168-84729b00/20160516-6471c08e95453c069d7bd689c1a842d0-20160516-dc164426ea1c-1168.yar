rule _20160516_6471c08e95453c069d7bd689c1a842d0_20160516_dc164426ea1c_1168 {
  meta:
    description = "datamaliciousorder - from files 20160516_6471c08e95453c069d7bd689c1a842d0.js, 20160516_dc164426ea1c5cac650135390822c48e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa506eeacd4512c55a6c3c18bbff460173b96100d277137382c77dfff96e3266"
    hash2       = "3f24d7d6adeefc8f97d10284db3a8fe32dea16a6809f06c8beaf844a81bbc1da"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* s  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* s  */ = 5316 - 5314;" fullword ascii
    $s3  = "CONNECTION /* s  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s4  = "Turkey = /* s  */(/* s  */\"noitisop\").split(''/* s  */).reverse(/* s  */).join('');" fullword ascii
    $s5  = "place0 /* s  */= true;/* s  */" fullword ascii
    $s6  = " var place /* s  */ = 3-2;" fullword ascii
    $s7  = "while (place /* s  */) { " fullword ascii
    $s8  = "for (;place /* s  */;){" fullword ascii
    $s9  = "if (place /* s  */ == 1)" fullword ascii
    $s10 = "place /* s  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}