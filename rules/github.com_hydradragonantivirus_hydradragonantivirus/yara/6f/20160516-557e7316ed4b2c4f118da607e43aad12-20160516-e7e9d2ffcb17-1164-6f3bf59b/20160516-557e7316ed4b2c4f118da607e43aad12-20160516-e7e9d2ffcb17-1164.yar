rule _20160516_557e7316ed4b2c4f118da607e43aad12_20160516_e7e9d2ffcb17_1164 {
  meta:
    description = "datamaliciousorder - from files 20160516_557e7316ed4b2c4f118da607e43aad12.js, 20160516_e7e9d2ffcb17e3f82b76f6a2082bdd59.js, 20160516_fdc97c7cf1ebb6f5acc8866a4edd24bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "822e19db7bd5c8a8e7a7f85db76c634dadc01ce9b93b7c3cce5a494a61564b93"
    hash2       = "9956136b30b06ea0812b942226046734e201960c289c403bc586ff33fd90b9b0"
    hash3       = "f4d824b660ee41cd0db7e1a9fab0d3417e9cd5b59a1c4f3a93bab4ee546b11ed"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* c  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* c  */ = 5316 - 5314;" fullword ascii
    $s3  = "Turkey = /* c  */(/* c  */\"noitisop\").split(''/* c  */).reverse(/* c  */).join('');" fullword ascii
    $s4  = "CONNECTION /* c  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s5  = "place0 /* c  */= true;/* c  */" fullword ascii
    $s6  = "while (place /* c  */) { " fullword ascii
    $s7  = "for (;place /* c  */;){" fullword ascii
    $s8  = "if (place /* c  */ == 1)" fullword ascii
    $s9  = " var place /* c  */ = 3-2;" fullword ascii
    $s10 = "place /* c  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}