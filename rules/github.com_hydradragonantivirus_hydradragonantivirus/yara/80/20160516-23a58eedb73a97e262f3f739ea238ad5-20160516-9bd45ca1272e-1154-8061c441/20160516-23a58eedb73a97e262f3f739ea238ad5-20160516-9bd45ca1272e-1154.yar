rule _20160516_23a58eedb73a97e262f3f739ea238ad5_20160516_9bd45ca1272e_1154 {
  meta:
    description = "datamaliciousorder - from files 20160516_23a58eedb73a97e262f3f739ea238ad5.js, 20160516_9bd45ca1272e605023bceaa2b9eaca98.js, 20160516_9cd4ba0694ecc3184869a7602e5c676e.js, 20160516_c715b4ee0e09aa942982a9a7f74cde18.js, 20160516_e296796727b69376102bf07fd3f3852d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b8e818008d51de9e031225450e3b2a84c3977b764420f5691cf38ae89601c43"
    hash2       = "bd30f1034d9cc205b3c13a8845734ab817fa1f15717fbb343223f87136a4b8bb"
    hash3       = "8315398d64ab74b09add7d226b20ea3ff84e94d6a774fde8d171b098815577ac"
    hash4       = "c815d59d0c6dff7e3fb71232021ea1b057d0c73a28ed983838915e2d7656fbe5"
    hash5       = "3b775349e7d2768a4c4c007c4ca71e23a572ddd5d16997a58383cd4560c136a6"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* I  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* I  */ = 5316 - 5314;" fullword ascii
    $s3  = "Turkey = /* I  */(/* I  */\"noitisop\").split(''/* I  */).reverse(/* I  */).join('');" fullword ascii
    $s4  = "CONNECTION /* I  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s5  = "if (place /* I  */ == 1)" fullword ascii
    $s6  = "place0 /* I  */= true;/* I  */" fullword ascii
    $s7  = " var place /* I  */ = 3-2;" fullword ascii
    $s8  = "for (;place /* I  */;){" fullword ascii
    $s9  = "while (place /* I  */) { " fullword ascii
    $s10 = "place /* I  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}