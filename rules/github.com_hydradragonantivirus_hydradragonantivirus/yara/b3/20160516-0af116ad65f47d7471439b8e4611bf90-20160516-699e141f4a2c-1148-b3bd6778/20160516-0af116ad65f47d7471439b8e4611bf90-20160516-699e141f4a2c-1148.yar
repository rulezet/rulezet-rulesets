rule _20160516_0af116ad65f47d7471439b8e4611bf90_20160516_699e141f4a2c_1148 {
  meta:
    description = "datamaliciousorder - from files 20160516_0af116ad65f47d7471439b8e4611bf90.js, 20160516_699e141f4a2c4d8e2341a1bfce6346ad.js, 20160516_7de222413d287dd1767394d037b827d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc70b414707adbf3bc53da32f9c65174c57452d9c318ae787ab36b6e136e5d09"
    hash2       = "4e59b8ead9464feb8b17a09e8f222f475a46c996dba77c7e80c0e9bb420b6277"
    hash3       = "5fb9e6f2c1eb4321c9c57dc61595261932cf7c894de2b9d1d8d814fd6336975c"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* X  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* X  */ = 5316 - 5314;" fullword ascii
    $s3  = "CONNECTION /* X  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s4  = "Turkey = /* X  */(/* X  */\"noitisop\").split(''/* X  */).reverse(/* X  */).join('');" fullword ascii
    $s5  = "for (;place /* X  */;){" fullword ascii
    $s6  = " var place /* X  */ = 3-2;" fullword ascii
    $s7  = "if (place /* X  */ == 1)" fullword ascii
    $s8  = "place0 /* X  */= true;/* X  */" fullword ascii
    $s9  = "while (place /* X  */) { " fullword ascii
    $s10 = "place /* X  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}