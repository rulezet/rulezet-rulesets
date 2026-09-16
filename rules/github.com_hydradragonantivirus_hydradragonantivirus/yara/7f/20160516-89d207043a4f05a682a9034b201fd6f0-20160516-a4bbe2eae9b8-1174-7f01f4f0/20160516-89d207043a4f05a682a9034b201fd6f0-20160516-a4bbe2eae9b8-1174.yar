rule _20160516_89d207043a4f05a682a9034b201fd6f0_20160516_a4bbe2eae9b8_1174 {
  meta:
    description = "datamaliciousorder - from files 20160516_89d207043a4f05a682a9034b201fd6f0.js, 20160516_a4bbe2eae9b8ce4ebffa6b233ff86412.js, 20160516_a69d5f13efd2a6a4d235e13cebf04661.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16691de441a96f02c20eeb6c24d47d70e4f1ee2332e3311f533e6f6321a6d7ce"
    hash2       = "277a116a4d8d005dcd70131c701e48bd7d3cd782c708aece077ac9e4abc2bcc9"
    hash3       = "ccd6511a6c7ddc29f5e153536557063d2cb6c89c3a165493827206e659fcd120"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* B  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* B  */ = 5316 - 5314;" fullword ascii
    $s3  = "Turkey = /* B  */(/* B  */\"noitisop\").split(''/* B  */).reverse(/* B  */).join('');" fullword ascii
    $s4  = "CONNECTION /* B  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s5  = "place0 /* B  */= true;/* B  */" fullword ascii
    $s6  = "for (;place /* B  */;){" fullword ascii
    $s7  = "while (place /* B  */) { " fullword ascii
    $s8  = " var place /* B  */ = 3-2;" fullword ascii
    $s9  = "if (place /* B  */ == 1)" fullword ascii
    $s10 = "place /* B  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}