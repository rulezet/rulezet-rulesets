rule _20160516_229ce506d05260144feb1e45506043ed_20160516_986d3430ef3f_1153 {
  meta:
    description = "datamaliciousorder - from files 20160516_229ce506d05260144feb1e45506043ed.js, 20160516_986d3430ef3f4dbfcce95a9d1bb11887.js, 20160516_ad2e931e83614e8ec8f4a4513a3ea2d0.js, 20160516_dfc8cbd36a53ba6a8fbab922b54db2fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c0d18557d60e71332b9ed185c5eaacc7b7fad1181c0afec234c4b7f43b9ea51"
    hash2       = "8062df26c65a09d3609f8dd2eb0bd8847c987d31796e9e4571e364ec24ccf056"
    hash3       = "205cb9358480f6ac011737514d5bc21f27093e1e30e7f81e60dda63fbff0ece2"
    hash4       = "b5c78643da5c56f4dc1467ca157f6a4ba62fdc14803b722abce50ea130bdea28"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* v  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* v  */ = 5316 - 5314;" fullword ascii
    $s3  = "Turkey = /* v  */(/* v  */\"noitisop\").split(''/* v  */).reverse(/* v  */).join('');" fullword ascii
    $s4  = "CONNECTION /* v  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s5  = " var place /* v  */ = 3-2;" fullword ascii
    $s6  = "for (;place /* v  */;){" fullword ascii
    $s7  = "if (place /* v  */ == 1)" fullword ascii
    $s8  = "place0 /* v  */= true;/* v  */" fullword ascii
    $s9  = "while (place /* v  */) { " fullword ascii
    $s10 = "place /* v  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}