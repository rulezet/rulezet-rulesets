rule sig_20160516_ba39a85e778dcdb52d1a534a3895fafd {
  meta:
    description = "datamaliciousorder - file 20160516_ba39a85e778dcdb52d1a534a3895fafd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e21610c6729732bdab4b3a2f29f2663f84427b7ed30b1004829a3ea87b6ad4f"

  strings:
    $s1  = "var fudge = [torpedo, store,derived,  \"\"+\".\"+(\"jacky\",\"screen\",\"dispersing\",\"terse\",\"ticking\",\"francis\",\"minist" ascii
    $s2  = "fakir = ((\"supply\", \"drivers\", \"travel\", \"navigation\", \"smyvYyk\") + \"MVouUfU\").messina2();" fullword ascii
    $s3  = "var tractable=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".messina4())&&loins[\"c3RhdHVz\".messina4()] +\"\"==\"MjAw\".messin" ascii
    $s4  = "weasel = ((\"socks\", \"bludgeon\", \"acceptable\", \"savory\", \"ECYcfTMHKvP\") + \"qAiUXM\").messina2();" fullword ascii
    $s5  = "String.prototype.messina4 = function() {" fullword ascii
    $s6  = "var sacrifice = fudge.pop().split(\"" fullword ascii
    $s7  = "String.prototype.messina2 = function () {" fullword ascii
    $s8  = "String.prototype.messina = function () {" fullword ascii
    $s9  = "            loins[fundamental]((\"monaco\",\"system\",\"G\" + weasel) + (\"oration\",\"craps\",\"webcam\",\"commented\",\"T\"), " ascii
    $s10 = "\",\"venture\",\"shell\",\"thrifty\",\"seventyeight\",\"accuses\",\"assailant\",\"2.\")+\"XM\"+\"LH\"+\"TT\"+(\"undefiled\",\"hu" ascii
    $s11 = "var fudge = [torpedo, store,derived,  \"\"+\".\"+(\"jacky\",\"screen\",\"dispersing\",\"terse\",\"ticking\",\"francis\",\"minist" ascii
    $s12 = "var store =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".messina4();" fullword ascii
    $s13 = "var derived =\"JVRFTVAl\".messina4();" fullword ascii
    $s14 = "var loins = new marred(sacrifice[0]);" fullword ascii
    $s15 = "armed = \"_F2_\";" fullword ascii
    $s16 = "te\",\"curtis\",\"advertising\",\"night\",\"08\"), fakir)] = 0;" fullword ascii
    $s17 = "        awning[(\"aztec\",\"orlando\",\"warwickshire\",\"massage\",\"unravel\",\"eternal\",\"reflective\",\"w\")+\"ri\"+\"te\"](" ascii
    $s18 = "var greater = new marred(sacrifice[1]);" fullword ascii
    $s19 = "function guarantees(mauve, royal) {" fullword ascii
    $s20 = "realism = this;" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}