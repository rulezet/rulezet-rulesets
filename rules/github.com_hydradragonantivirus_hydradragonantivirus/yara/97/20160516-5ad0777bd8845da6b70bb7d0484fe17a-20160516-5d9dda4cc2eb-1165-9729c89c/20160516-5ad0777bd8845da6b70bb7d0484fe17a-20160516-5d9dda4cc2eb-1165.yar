rule _20160516_5ad0777bd8845da6b70bb7d0484fe17a_20160516_5d9dda4cc2eb_1165 {
  meta:
    description = "datamaliciousorder - from files 20160516_5ad0777bd8845da6b70bb7d0484fe17a.js, 20160516_5d9dda4cc2ebc744b854d2b35dbcd0c5.js, 20160516_853237fae31b1eeefb65f0ee177e2792.js, 20160516_c68b5659b68b3d377a210b37de663072.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05327265a38748b357d9059a8377baa6de9da25a52e41885a87ba913772d5e9f"
    hash2       = "37be892524945ba588825d009d759d0bd14c1f5932f8912f0e3f7a7d81f19628"
    hash3       = "6197ee5887a61b7eb5446dbca31c4289063c8d5987a41359a028bbcae5ae8b3f"
    hash4       = "bc1b24b10fea6db7feb64f0fa853efb93d6797d1f15dffedd1edbade5198d067"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* L  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* L  */ = 5316 - 5314;" fullword ascii
    $s3  = "Turkey = /* L  */(/* L  */\"noitisop\").split(''/* L  */).reverse(/* L  */).join('');" fullword ascii
    $s4  = "CONNECTION /* L  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s5  = "while (place /* L  */) { " fullword ascii
    $s6  = "for (;place /* L  */;){" fullword ascii
    $s7  = "if (place /* L  */ == 1)" fullword ascii
    $s8  = " var place /* L  */ = 3-2;" fullword ascii
    $s9  = "place0 /* L  */= true;/* L  */" fullword ascii
    $s10 = "place /* L  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}