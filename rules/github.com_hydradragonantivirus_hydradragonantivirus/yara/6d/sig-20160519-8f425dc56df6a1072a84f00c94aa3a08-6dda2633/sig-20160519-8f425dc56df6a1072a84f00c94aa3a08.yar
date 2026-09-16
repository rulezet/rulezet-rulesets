rule sig_20160519_8f425dc56df6a1072a84f00c94aa3a08 {
  meta:
    description = "datamaliciousorder - file 20160519_8f425dc56df6a1072a84f00c94aa3a08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7f9cdcaaa10c70ce7d9d4b0c78a61b81364c112dc02ea1986dc20d4403d5da0"

  strings:
    $s1  = "var warranty = [accessory, origins,responsible,  \"\"+\".\"+(\"michael\",\"bowling\",\"opera\",\"arlington\",\"focal\",\"educato" ascii
    $s2  = "weasel = ((\"therapist\", \"loath\", \"formed\", \"operate\", \"Eysipvldhp\") + \"bprSkr\").phlegm2();" fullword ascii
    $s3  = "lightweight(\"aHR0cDovLw==\".phlegm4()+\"\\u0077\\u0077\\u0077\\u002E\\u0074\\u0065\\u006C\\u0065\\u0073\\u0063\\u0061\\u0064\\u" ascii
    $s4  = "basement = basement+ warranty.shift();" fullword ascii
    $s5  = "    solidarity[secondrate + (\"banking\",\"circumcision\",\"end\")]();" fullword ascii
    $s6  = "function lightweight(profits, component) {" fullword ascii
    $s7  = "var correcting = warranty.pop().split(\">\");" fullword ascii
    $s8  = "String.prototype.phlegm = function () {" fullword ascii
    $s9  = "String.prototype.phlegm2 = function () {" fullword ascii
    $s10 = "String.prototype.phlegm4 = function() {" fullword ascii
    $s11 = "        var basement = favorably + \"/\" + component ;" fullword ascii
    $s12 = "var canes=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".phlegm4())&&solidarity[\"c3RhdHVz\".phlegm4()] +\"\"==\"MjAw\".phlegm4" ascii
    $s13 = "var canes=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".phlegm4())&&solidarity[\"c3RhdHVz\".phlegm4()] +\"\"==\"MjAw\".phlegm4" ascii
    $s14 = "var warranty = [accessory, origins,responsible,  \"\"+\".\"+(\"michael\",\"bowling\",\"opera\",\"arlington\",\"focal\",\"educato" ascii
    $s15 = "var solidarity = new freeze(correcting[0]);" fullword ascii
    $s16 = "var accessory = \"QWbitchN0aXZbitchlWE9iabitchmVjdA=bitch=\".phlegm4();" fullword ascii
    $s17 = "        abnormally[\"d3JpdGU=\".phlegm4()](solidarity[(\"samba\",\"bentley\",\"duality\",\"aurora\",\"nevermore\",\"content\",\"" ascii
    $s18 = "var freeze = this[warranty.shift()];" fullword ascii
    $s19 = "var fascinating = {" fullword ascii
    $s20 = "ts, false);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}