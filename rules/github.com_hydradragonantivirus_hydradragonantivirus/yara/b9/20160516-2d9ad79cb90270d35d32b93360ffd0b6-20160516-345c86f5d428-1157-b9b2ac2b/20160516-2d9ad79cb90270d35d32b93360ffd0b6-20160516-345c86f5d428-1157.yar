rule _20160516_2d9ad79cb90270d35d32b93360ffd0b6_20160516_345c86f5d428_1157 {
  meta:
    description = "datamaliciousorder - from files 20160516_2d9ad79cb90270d35d32b93360ffd0b6.js, 20160516_345c86f5d428635a0ea1ae5195680c6b.js, 20160516_8291d0c7929e9f667a31134147b39d31.js, 20160516_88ef8a461af76c8db871bfe40b69ba0c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c4b27f990a93a6bf2ffbbbccf9d0616c3888be5a470347c2542f20b662b9439"
    hash2       = "580e3cac2b9bacbc7aa15dc90cc26381b1056a0d72534d0ed827f02bf1128abc"
    hash3       = "5d6f052cfe0ff1cfe5b2a3cb3cc92f9ac0d69a88d8a3a4cf581189f00d3e618f"
    hash4       = "6ad3e1adb723ec81a0c4962e96cc03bea377390e54a1e4b3de7e453c3e07b424"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* x  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* x  */ = 5316 - 5314;" fullword ascii
    $s3  = "Turkey = /* x  */(/* x  */\"noitisop\").split(''/* x  */).reverse(/* x  */).join('');" fullword ascii
    $s4  = "CONNECTION /* x  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s5  = "for (;place /* x  */;){" fullword ascii
    $s6  = "if (place /* x  */ == 1)" fullword ascii
    $s7  = "place0 /* x  */= true;/* x  */" fullword ascii
    $s8  = " var place /* x  */ = 3-2;" fullword ascii
    $s9  = "while (place /* x  */) { " fullword ascii
    $s10 = "place /* x  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}