rule sig_20160517_9f7d9b2963f78dc07a60c0a8b52fdc93 {
  meta:
    description = "datamaliciousorder - file 20160517_9f7d9b2963f78dc07a60c0a8b52fdc93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "961c32f51fc882e0a02e4d53a7d014dbbf406f75502f32ee79d0bbe90fcee0c5"

  strings:
    $s1  = "var invisible = new comer(henceforward[0]);" fullword ascii
    $s2  = "var henceforward = parasol.pop().split(\"" fullword ascii
    $s3  = "var fastidious = new comer(henceforward[1]);" fullword ascii
    $s4  = "var pedantry=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".malay4())&&invisible[\"c3RhdHVz\".malay4()] +\"\"==\"MjAw\".malay4(" ascii
    $s5  = "var pedantry=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".malay4())&&invisible[\"c3RhdHVz\".malay4()] +\"\"==\"MjAw\".malay4(" ascii
    $s6  = "circumlocution = this;" fullword ascii
    $s7  = "for (var i in healthy){circumlocution = circumlocution.replace(i, healthy[i]);}" fullword ascii
    $s8  = "ordain = ((\"expenses\", \"oyster\", \"dance\", \"incipient\", \"sDPSeEthx\") + \"SkPQWNBgmW\").malay2();" fullword ascii
    $s9  = "thorax(\"aHR0cDovLw==\".malay4()+\"\\u006B\\u0061\\u0074\\u0079\\u0063\\u006F\\u002E\\u006E\\u0065\"+\"\\u0074\\u002F\\u0030\\u0" ascii
    $s10 = "            invisible[reindeer]((\"aromatic\",\"fruits\",\"G\" + weasel) + (\"inborn\",\"mario\",\"cosmos\",\"genealogy\",\"T\")" ascii
    $s11 = "information = information+ parasol.shift();" fullword ascii
    $s12 = "            invisible[reindeer]((\"aromatic\",\"fruits\",\"G\" + weasel) + (\"inborn\",\"mario\",\"cosmos\",\"genealogy\",\"T\")" ascii
    $s13 = "var comer = this[parasol.shift()];" fullword ascii
    $s14 = "ational\",\"s\")+\"ubRt\"+(\"render\",\"standing\",\"lariat\",\"derek\",\"media\",\"commodity\",\"parsimonious\",\"ri\")+\"ng\")" ascii
    $s15 = "String.prototype.malay4 = function() {" fullword ascii
    $s16 = "String.prototype.malay = function () {" fullword ascii
    $s17 = "String.prototype.malay2 = function () {" fullword ascii
    $s18 = "var ostend = fastidious[parasol.shift()](parasol.shift());" fullword ascii
    $s19 = "var schedule =\"JVbundleRFTVbundleAl\".malay4();" fullword ascii
    $s20 = "function thorax(closeted, metaphysics) {" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}