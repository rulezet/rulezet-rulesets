rule sig_20160516_59b32141b18543c5d3b7df2e3169b57e {
  meta:
    description = "datamaliciousorder - file 20160516_59b32141b18543c5d3b7df2e3169b57e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78c59970e86d73f74091020f2bd3b620f81bf34fc86334327e86bcd12b59abc1"

  strings:
    $s1  = "var insurmountable=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".ascension4())&&satrap[\"c3RhdHVz\".ascension4()] +\"\"==\"MjA" ascii
    $s2  = "var insurmountable=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".ascension4())&&satrap[\"c3RhdHVz\".ascension4()] +\"\"==\"MjA" ascii
    $s3  = "var marianne = [excited, expanded,tangible,  \"\"+\".\"+(\"margot\",\"enamored\",\"barbara\",\"heterodox\",\"seasonal\",\"unfore" ascii
    $s4  = "consonant(\"aHR0cDovLw==\".ascension4()+\"\\u0062\\u006C\\u006F\\u0032\\u0030\\u0030\\u0030\\u002E\\u0067\\u006C\\u0075\\u0070" ascii
    $s5  = "String.prototype.ascension4 = function() {" fullword ascii
    $s6  = "String.prototype.ascension2 = function () {" fullword ascii
    $s7  = "var school = marianne.pop().split(\"" fullword ascii
    $s8  = "String.prototype.ascension = function () {" fullword ascii
    $s9  = "    satrap[potash + (\"detail\",\"versions\",\"end\")]();" fullword ascii
    $s10 = "        var shopzilla = new tickle(((\"passer\",\"actress\",\"flaxen\",\"ludwig\",\"approximately\",\"vertebrate\",\"complacent" ascii
    $s11 = "\"ubRt\"+(\"dayton\",\"postage\",\"cravat\",\"singh\",\"brothel\",\"dexterous\",\"males\",\"ri\")+\"ng\").replace(\"R\", lombard" ascii
    $s12 = "        var shopzilla = new tickle(((\"passer\",\"actress\",\"flaxen\",\"ludwig\",\"approximately\",\"vertebrate\",\"complacent" ascii
    $s13 = "for (var i in lombard){agitator = agitator.replace(i, lombard[i]);}" fullword ascii
    $s14 = "var dauntless = new tickle(school[1]);" fullword ascii
    $s15 = "  consistence = [];" fullword ascii
    $s16 = "senior = \"_F2_\";" fullword ascii
    $s17 = "dauntless[marianne.shift()](roommates, bullying, true);RrcbrXSYvrJ = \"_F17_\";" fullword ascii
    $s18 = "var expanded =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".ascension4();" fullword ascii
    $s19 = "weasel = ((\"licensing\", \"misgivings\", \"erotic\", \"scary\", \"EMckCJrNOg\") + \"yxitict\").ascension2();" fullword ascii
    $s20 = "var lombard = {" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}