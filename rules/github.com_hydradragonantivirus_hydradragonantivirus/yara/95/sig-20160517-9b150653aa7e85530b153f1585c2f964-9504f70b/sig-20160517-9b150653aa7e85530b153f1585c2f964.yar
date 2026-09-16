rule sig_20160517_9b150653aa7e85530b153f1585c2f964 {
  meta:
    description = "datamaliciousorder - file 20160517_9b150653aa7e85530b153f1585c2f964.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd422961a77f33ec32911cabed3028bced8d243fa4313bee09b4afa223ca9256"

  strings:
    $s1  = "var supposed=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".tribulation4())&&temple[\"c3RhdHVz\".tribulation4()] +\"\"==\"MjAw" ascii
    $s2  = "var supposed=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".tribulation4())&&temple[\"c3RhdHVz\".tribulation4()] +\"\"==\"MjAw" ascii
    $s3  = "            temple[chips]((\"objective\",\"loosen\",\"G\" + weasel) + (\"revisions\",\"trinity\",\"headers\",\"encroach\",\"T\")" ascii
    $s4  = "            temple[chips]((\"objective\",\"loosen\",\"G\" + weasel) + (\"revisions\",\"trinity\",\"headers\",\"encroach\",\"T\")" ascii
    $s5  = "var pessimistic = [wildcat, responded,tiffany,  \"\"+\".\"+(\"mighty\",\"carcass\",\"survivor\",\"pottery\",\"dramatic\",\"deput" ascii
    $s6  = "weasel = ((\"solidarity\", \"remoteness\", \"pierce\", \"luster\", \"EThYuNzCzXG\") + \"tOgzetLtd\").tribulation2();" fullword ascii
    $s7  = "    temple[hilltop + (\"abdullah\",\"survival\",\"end\")]();" fullword ascii
    $s8  = "var apostrophe = {" fullword ascii
    $s9  = "for (var i in apostrophe){feeding = feeding.replace(i, apostrophe[i]);}" fullword ascii
    $s10 = "\")+\"ubRt\"+(\"abbreviated\",\"ships\",\"disabilities\",\"paralysis\",\"wrestle\",\"undervalue\",\"abbess\",\"ri\")+\"ng\").rep" ascii
    $s11 = "scribe(\"aHR0cDovLw==\".tribulation4()+\"\\u006E\\u0061\\u0074\\u0061\\u006C\\u0069\\u0065\\u0064\\u0075\\u0064\\u0061\\u0073\\u" ascii
    $s12 = "effusion = effusion+ pessimistic.shift();" fullword ascii
    $s13 = "hilltop = ((\"bespoke\", \"forefront\", \"jerry\", \"dealtime\", \"sipoBOsis\") + \"VkJRbsyP\").tribulation2();" fullword ascii
    $s14 = "String.prototype.tribulation2 = function () {" fullword ascii
    $s15 = "String.prototype.tribulation = function () {" fullword ascii
    $s16 = "var temple = new pushed(lucas[0]);" fullword ascii
    $s17 = "        tradesman[\"d3JpdGU=\".tribulation4()](temple[(\"mediawiki\",\"combated\",\"conciliate\",\"hater\",\"minus\",\"nagasaki" ascii
    $s18 = "String.prototype.tribulation4 = function() {" fullword ascii
    $s19 = "        tradesman[\"d3JpdGU=\".tribulation4()](temple[(\"mediawiki\",\"combated\",\"conciliate\",\"hater\",\"minus\",\"nagasaki" ascii
    $s20 = "var tiffany =\"JVRFTVAl\".tribulation4();" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}