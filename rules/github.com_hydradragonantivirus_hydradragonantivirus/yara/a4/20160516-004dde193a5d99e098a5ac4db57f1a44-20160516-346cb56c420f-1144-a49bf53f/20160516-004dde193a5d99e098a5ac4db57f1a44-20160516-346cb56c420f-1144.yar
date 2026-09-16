rule _20160516_004dde193a5d99e098a5ac4db57f1a44_20160516_346cb56c420f_1144 {
  meta:
    description = "datamaliciousorder - from files 20160516_004dde193a5d99e098a5ac4db57f1a44.js, 20160516_346cb56c420fea509ca8da55f5f3a161.js, 20160516_36e6462614302c5877082f0be084f3d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "269d25729fe6eb945ec3cf044668b3318d73bacb034106ec8460a8a1a9dc2b13"
    hash2       = "c900e7c89280cebb0cefd9bc01c2407b2c94fac327b4ceafb0073203e4ec2946"
    hash3       = "5b057d1d09827da026c22d3e6ab9de5a7077471537471e5b49bdd09ce638b3bf"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* l  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* l  */ = 5316 - 5314;" fullword ascii
    $s3  = "Turkey = /* l  */(/* l  */\"noitisop\").split(''/* l  */).reverse(/* l  */).join('');" fullword ascii
    $s4  = "CONNECTION /* l  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s5  = " var place /* l  */ = 3-2;" fullword ascii
    $s6  = "for (;place /* l  */;){" fullword ascii
    $s7  = "if (place /* l  */ == 1)" fullword ascii
    $s8  = "while (place /* l  */) { " fullword ascii
    $s9  = "place0 /* l  */= true;/* l  */" fullword ascii
    $s10 = "place /* l  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}