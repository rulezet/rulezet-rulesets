rule _20160516_9cf687534eab21cfc3240bc41abc7dd7_20160516_d0c78fdb5797_1175 {
  meta:
    description = "datamaliciousorder - from files 20160516_9cf687534eab21cfc3240bc41abc7dd7.js, 20160516_d0c78fdb5797b7b870824e3817c1b2a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb5a3e071c5b58423fcfa5441a9749e713f78fcbcc5732a600ecd3ac6453c0ea"
    hash2       = "f6a7fb975566da824eb08c6caab22ac5fe04d02490976fae8db88ce894073166"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* r  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* r  */ = 5316 - 5314;" fullword ascii
    $s3  = "Turkey = /* r  */(/* r  */\"noitisop\").split(''/* r  */).reverse(/* r  */).join('');" fullword ascii
    $s4  = "CONNECTION /* r  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s5  = "while (place /* r  */) { " fullword ascii
    $s6  = "for (;place /* r  */;){" fullword ascii
    $s7  = " var place /* r  */ = 3-2;" fullword ascii
    $s8  = "if (place /* r  */ == 1)" fullword ascii
    $s9  = "place0 /* r  */= true;/* r  */" fullword ascii
    $s10 = "place /* r  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}