rule sig_20160519_6388db0964148d76b49120e1cf5d043e {
  meta:
    description = "datamaliciousorder - file 20160519_6388db0964148d76b49120e1cf5d043e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3fc2750014c36aa0dc930295e2036c7f44f398ff21b9adce074c36f4a75924b"

  strings:
    $s1  = "var carol = [parsley, authorities,mediocrity,  \"\"+\".\"+(\"sullivan\",\"intel\",\"inquisitively\",\"direction\",\"appendage\"," ascii
    $s2  = "var estrangement=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".impression4())&&festival[\"c3RhdHVz\".impression4()] +\"\"==\"M" ascii
    $s3  = "var estrangement=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".impression4())&&festival[\"c3RhdHVz\".impression4()] +\"\"==\"M" ascii
    $s4  = ",\"jesse\",\"cr\")+(\"distribution\",\"lovable\",\"publications\",\"cassette\",\"recede\",\"medicare\",\"lotus\",\"directors\"," ascii
    $s5  = "browse(\"aHR0cDovLw==\".impression4()+\"\\u007A\\u0061\\u0072\\u0061\\u0062\\u006F\\u0074\\u0061\\u0074\\u002E\\u0079\\u006F\\u0" ascii
    $s6  = "weasel = ((\"cumshots\", \"tomato\", \"deutsche\", \"glorify\", \"ExGaetIocSu\") + \"UhpssddEE\").impression2();" fullword ascii
    $s7  = "String.prototype.impression4 = function() {" fullword ascii
    $s8  = "String.prototype.impression2 = function () {" fullword ascii
    $s9  = "String.prototype.impression = function () {" fullword ascii
    $s10 = "for (var i in probation){bodyguard = bodyguard.replace(i, probation[i]);}" fullword ascii
    $s11 = "unbridled = \"_F2_\";" fullword ascii
    $s12 = "browse(\"aHR0cDovLw==\".impression4()+\"\\u007A\\u0061\\u0072\\u0061\\u0062\\u006F\\u0074\\u0061\\u0074\\u002E\\u0079\\u006F\\u0" ascii
    $s13 = "var buttons = 0;" fullword ascii
    $s14 = "var festival = new destiny(school[0]);" fullword ascii
    $s15 = "potash = \"b3Blbg==\".impression4();" fullword ascii
    $s16 = "  bottom = [];" fullword ascii
    $s17 = "var footnote = new destiny(school[1]);" fullword ascii
    $s18 = "function browse(winder, vomit) {" fullword ascii
    $s19 = "bodyguard = this;" fullword ascii
    $s20 = "var probation = {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}