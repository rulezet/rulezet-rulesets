rule _20160516_2f52b142d14ec8ad38160fd1f9634a5a_20160516_9135d6382aca_1158 {
  meta:
    description = "datamaliciousorder - from files 20160516_2f52b142d14ec8ad38160fd1f9634a5a.js, 20160516_9135d6382aca86c047edea62d7c40f94.js, 20160516_bc515b858c8b68bc7de713497eba59f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcbcc796099d6a60100cf757332a9cb606af5c9a2d85518b4c5ef27f0385ee30"
    hash2       = "04b05e9ee62f298aa395eaa38ca15fd63e20d78f5136aa2f81e6d96d4a8663bd"
    hash3       = "4cd3d8dcbefc752458dcfcbbcf5633fdd0aa89538f6a352bd634721f229b4ed7"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* G  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* G  */ = 5316 - 5314;" fullword ascii
    $s3  = "CONNECTION /* G  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s4  = "Turkey = /* G  */(/* G  */\"noitisop\").split(''/* G  */).reverse(/* G  */).join('');" fullword ascii
    $s5  = " var place /* G  */ = 3-2;" fullword ascii
    $s6  = "if (place /* G  */ == 1)" fullword ascii
    $s7  = "while (place /* G  */) { " fullword ascii
    $s8  = "for (;place /* G  */;){" fullword ascii
    $s9  = "place0 /* G  */= true;/* G  */" fullword ascii
    $s10 = "place /* G  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}