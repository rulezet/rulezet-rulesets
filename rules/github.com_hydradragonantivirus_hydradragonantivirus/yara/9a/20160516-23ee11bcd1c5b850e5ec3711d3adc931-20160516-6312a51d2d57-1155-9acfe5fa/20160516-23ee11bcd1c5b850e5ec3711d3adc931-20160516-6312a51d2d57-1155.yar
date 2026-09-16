rule _20160516_23ee11bcd1c5b850e5ec3711d3adc931_20160516_6312a51d2d57_1155 {
  meta:
    description = "datamaliciousorder - from files 20160516_23ee11bcd1c5b850e5ec3711d3adc931.js, 20160516_6312a51d2d57f6f2871f49db8b3f82e5.js, 20160516_742dc4de751772ff04bec1a36f79cde7.js, 20160516_a049560b410387c42b1efec3b5357c7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fabbe67c7394e2c754c811d9c4888fd6fb90432cb0fc70a5e2f348d3892b822d"
    hash2       = "afdfe33edec39a58f8652a026c275bedb690cd512705e4666ea19860e8c3be08"
    hash3       = "3abfeac9138471ca8961c21516f694bb50dcbeb5fd9051c491f6756054fd365a"
    hash4       = "be0c5aff29116a83e461e3669136caf88b68cc64c6179ac9dcf44a9448b94fe4"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* C  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* C  */ = 5316 - 5314;" fullword ascii
    $s3  = "CONNECTION /* C  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s4  = "Turkey = /* C  */(/* C  */\"noitisop\").split(''/* C  */).reverse(/* C  */).join('');" fullword ascii
    $s5  = " var place /* C  */ = 3-2;" fullword ascii
    $s6  = "while (place /* C  */) { " fullword ascii
    $s7  = "place0 /* C  */= true;/* C  */" fullword ascii
    $s8  = "for (;place /* C  */;){" fullword ascii
    $s9  = "if (place /* C  */ == 1)" fullword ascii
    $s10 = "place /* C  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}