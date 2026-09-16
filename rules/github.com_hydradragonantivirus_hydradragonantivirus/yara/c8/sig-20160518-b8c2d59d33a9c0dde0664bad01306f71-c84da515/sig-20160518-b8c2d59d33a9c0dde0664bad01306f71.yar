rule sig_20160518_b8c2d59d33a9c0dde0664bad01306f71 {
  meta:
    description = "datamaliciousorder - file 20160518_b8c2d59d33a9c0dde0664bad01306f71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6749b84133f09912f0de6899099221e77d8bfd70d4ca298a630e9bb4e609735e"

  strings:
    $s1  = "var unsympathetic = [crosswise, input,recorder,  \"\"+\".\"+(\"transmission\",\"guitar\",\"goggles\",\"positioning\",\"unnecessa" ascii
    $s2  = "var propagating=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".debase4())&&syllogism[\"c3RhdHVz\".debase4()] +\"\"==\"MjAw\".de" ascii
    $s3  = "var propagating=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".debase4())&&syllogism[\"c3RhdHVz\".debase4()] +\"\"==\"MjAw\".de" ascii
    $s4  = "            syllogism[semicircle]((\"cracking\",\"exposure\",\"G\" + weasel) + (\"wheat\",\"laudable\",\"confirmed\",\"vernacula" ascii
    $s5  = "            syllogism[semicircle]((\"cracking\",\"exposure\",\"G\" + weasel) + (\"wheat\",\"laudable\",\"confirmed\",\"vernacula" ascii
    $s6  = "weasel = ((\"incomparable\", \"resolve\", \"wiring\", \"hearts\", \"EeKzWSVGWuDT\") + \"UKnNAoxO\").debase2();" fullword ascii
    $s7  = "semicircle = \"b3Blbg==\".debase4();;" fullword ascii
    $s8  = "var syllogism = new reprint(briton[0]);" fullword ascii
    $s9  = "dietary = ((\"collaboration\", \"closest\", \"deter\", \"pharmacy\", \"sjlKzsdf\") + \"cTYswR\").debase2();" fullword ascii
    $s10 = "    syllogism[dietary + (\"emptiness\",\"incubation\",\"end\")]();" fullword ascii
    $s11 = "efface(\"aHR0cDovLw==\".debase4()+\"\\u006F\\u006C\\u0067\\u0061\\u0073\\u0074\\u0075\\u0064\\u0069\\u006F\"+\"\\u002E\\u0072\\u" ascii
    $s12 = "plaintiff = ((\"mongolian\", \"fewer\", \"stipulate\", \"participating\", \"pgqyIcxOKG\") + \"trSvVBW\").debase2();" fullword ascii
    $s13 = "String.prototype.debase = function () {" fullword ascii
    $s14 = "String.prototype.debase2 = function () {" fullword ascii
    $s15 = "String.prototype.debase4 = function() {" fullword ascii
    $s16 = "\",\"A\")+(\"writhe\",\"lexington\",\"gratuit\",\"inquisitor\",\"wallpapers\",\"underwent\",\"sulkily\",\"shrivel\",\"SEOO\")+\"" ascii
    $s17 = "n, false);" fullword ascii
    $s18 = "var recorder =\"JVveldtRFTVveldtAl\".debase4();" fullword ascii
    $s19 = "var delineate = 0;" fullword ascii
    $s20 = "migration = this;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}