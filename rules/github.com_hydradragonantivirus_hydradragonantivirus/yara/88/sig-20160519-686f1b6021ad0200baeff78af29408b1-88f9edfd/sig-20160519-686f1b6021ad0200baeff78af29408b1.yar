rule sig_20160519_686f1b6021ad0200baeff78af29408b1 {
  meta:
    description = "datamaliciousorder - file 20160519_686f1b6021ad0200baeff78af29408b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55ab022560652167a139a53e5ea65168857e76312e4361afc36d9ca2de2acbf9"

  strings:
    $s1  = "var ezekiel = [compute, harbor,dayton,  \"\"+\".\"+(\"posting\",\"tracker\",\"users\",\"bases\",\"greenland\",\"mandolin\",\"pos" ascii
    $s2  = "var ezekiel = [compute, harbor,dayton,  \"\"+\".\"+(\"posting\",\"tracker\",\"users\",\"bases\",\"greenland\",\"mandolin\",\"pos" ascii
    $s3  = "var aborigines=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".prefers4())&&unnecessary[\"c3RhdHVz\".prefers4()] +\"\"==\"MjAw\"" ascii
    $s4  = "var aborigines=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".prefers4())&&unnecessary[\"c3RhdHVz\".prefers4()] +\"\"==\"MjAw\"" ascii
    $s5  = "        var heartrending = new insincere(((\"releases\",\"vincent\",\"inflection\",\"stevens\",\"acrylic\",\"evident\",\"expande" ascii
    $s6  = "crestfallen(\"aHR0cDovLw==\".prefers4()+\"\\u0070\\u0069\\u0070\\u0074\\u002E\\u0077\\u0061\\u006C\\u006C\\u0073\\u0074\\u002E\"" ascii
    $s7  = "weasel = ((\"muslim\", \"automatic\", \"greetings\", \"daughter\", \"EoCuPLpp\") + \"bHOckO\").prefers2();" fullword ascii
    $s8  = "var passively = aimless[ezekiel.shift()](ezekiel.shift());" fullword ascii
    $s9  = "String.prototype.prefers4 = function() {" fullword ascii
    $s10 = "var compute = \"QWcorsetN0aXZcorsetlWE9iacorsetmVjdA=corset=\".prefers4();" fullword ascii
    $s11 = "String.prototype.prefers2 = function () {" fullword ascii
    $s12 = "String.prototype.prefers = function () {" fullword ascii
    $s13 = "var predict = ezekiel.pop().split(\">\");" fullword ascii
    $s14 = "        var jacob = passively + \"/\" + ninetynine ;" fullword ascii
    $s15 = "joint = \"_F2_\";" fullword ascii
    $s16 = "var unnecessary = new insincere(predict[0]);" fullword ascii
    $s17 = "function crestfallen(pervert, ninetynine) {" fullword ascii
    $s18 = "var liberty = 0;" fullword ascii
    $s19 = "var harbor =\"RXhwYW5corsetkRW52aXcorsetJvbm1lbnRTdHJcorsetpbmdz\".prefers4();" fullword ascii
    $s20 = "var insincere = this[ezekiel.shift()];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}