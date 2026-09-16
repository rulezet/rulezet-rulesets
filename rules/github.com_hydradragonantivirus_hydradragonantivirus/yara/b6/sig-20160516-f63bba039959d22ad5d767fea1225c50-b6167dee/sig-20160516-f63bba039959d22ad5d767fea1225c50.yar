rule sig_20160516_f63bba039959d22ad5d767fea1225c50 {
  meta:
    description = "datamaliciousorder - file 20160516_f63bba039959d22ad5d767fea1225c50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81f3472d41f3f6e10b311dfb01677f17e2febc66862fd63584614dd98dee85a3"

  strings:
    $s1  = "var operatic =\"JVRFTVAl\".rousing4();" fullword ascii
    $s2  = "var cattleman = [antechamber, alternative,operatic,  \"\"+\".\"+(\"flickr\",\"bandy\",\"secretive\",\"dower\",\"invoke\",\"purgi" ascii
    $s3  = "weasel = ((\"crumb\", \"furtherance\", \"scenes\", \"putty\", \"EnPanrFQrl\") + \"OiSDnxgri\").rousing2();" fullword ascii
    $s4  = "court = ((\"benignant\", \"trooper\", \"excellence\", \"mating\", \"pGBqFdwlHij\") + \"xkXyQmLpUW\").rousing2();" fullword ascii
    $s5  = "var cattleman = [antechamber, alternative,operatic,  \"\"+\".\"+(\"flickr\",\"bandy\",\"secretive\",\"dower\",\"invoke\",\"purgi" ascii
    $s6  = "String.prototype.rousing2 = function () {" fullword ascii
    $s7  = "String.prototype.rousing4 = function() {" fullword ascii
    $s8  = "String.prototype.rousing = function () {" fullword ascii
    $s9  = "        corkscrew[(\"completes\",\"footstep\",\"tissue\",\"laden\",\"coordinated\",\"couples\",\"valid\",\"w\")+\"ri\"+\"te\"](r" ascii
    $s10 = "var spherical=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".rousing4())&&really[\"c3RhdHVz\".rousing4()] +\"\"==\"MjAw\".rousi" ascii
    $s11 = "var spherical=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".rousing4())&&really[\"c3RhdHVz\".rousing4()] +\"\"==\"MjAw\".rousi" ascii
    $s12 = "        corkscrew[(\"completes\",\"footstep\",\"tissue\",\"laden\",\"coordinated\",\"couples\",\"valid\",\"w\")+\"ri\"+\"te\"](r" ascii
    $s13 = "hover = this;" fullword ascii
    $s14 = "for (var i in directors){hover = hover.replace(i, directors[i]);}" fullword ascii
    $s15 = "lecturer = \"_F2_\";" fullword ascii
    $s16 = "thereof = thereof+ cattleman.shift();" fullword ascii
    $s17 = "var aquatic = 0;" fullword ascii
    $s18 = "motherless = \"b3Blbg==\".rousing4();;" fullword ascii
    $s19 = "var alternative =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".rousing4();" fullword ascii
    $s20 = "var antechamber = \"QWN0aXZlWE9iamVjdA==\".rousing4();" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}