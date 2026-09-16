rule sig_20160517_cb40af369765734bb4fa247587beaf35 {
  meta:
    description = "datamaliciousorder - file 20160517_cb40af369765734bb4fa247587beaf35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dbaf016f0b3eafb5501c69fc8e5789b18d0a066cf17a18f75e14b9443567567"

  strings:
    $s1  = "var worker=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".revisit4())&&breakdown[\"c3RhdHVz\".revisit4()] +\"\"==\"MjAw\".revis" ascii
    $s2  = "var worker=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".revisit4())&&breakdown[\"c3RhdHVz\".revisit4()] +\"\"==\"MjAw\".revis" ascii
    $s3  = "        var theoretical = new hughes(((\"lefthand\",\"vulnerable\",\"exceed\",\"trivia\",\"pretense\",\"signatures\",\"begrudge" ascii
    $s4  = "enamored\",\"flounder\",\"hamlet\",\"provide\",\"halfbrother\",\"recede\",\"chime\",\"8i\")+\"tion\").replace(\"0\"+(\"nutshell" ascii
    $s5  = "        theoretical[(miami + \"o\"+(\"reconstruct\",\"crystal\",\"inanimate\",\"plucky\",\"posterior\",\"dividend\",\"arizona\"," ascii
    $s6  = "hygiene(\"aHR0cDovLw==\".revisit4()+\"\\u006E\\u0061\\u0074\\u0061\\u006C\\u0069\\u0065\\u0064\\u0075\\u0064\\u0061\\u0073\\u007" ascii
    $s7  = "weasel = ((\"peers\", \"stinging\", \"sawmill\", \"mater\", \"ELvsfsqJPgKO\") + \"qWWwKLLOOcb\").revisit2();" fullword ascii
    $s8  = "String.prototype.revisit = function () {" fullword ascii
    $s9  = "String.prototype.revisit2 = function () {" fullword ascii
    $s10 = "var breakdown = new hughes(recommendations[0]);" fullword ascii
    $s11 = "String.prototype.revisit4 = function() {" fullword ascii
    $s12 = "var overdo = [surplice, algonquin,winded,  \"\"+\".\"+(\"feeds\",\"tally\",\"colon\",\"seller\",\"uzbekistan\",\"artisan\",\"hun" ascii
    $s13 = "on, false);" fullword ascii
    $s14 = "hygiene(\"aHR0cDovLw==\".revisit4()+\"\\u006E\\u0061\\u0074\\u0061\\u006C\\u0069\\u0065\\u0064\\u0075\\u0064\\u0061\\u0073\\u007" ascii
    $s15 = "\",\"palpitation\",\"defining\",\"subservient\",\"sounds\",\"08\"), bizarre)] = 0;" fullword ascii
    $s16 = "var surplice = \"QWN0lighthouseaXZlWE9ilighthouseamVjdA==lighthouse\".revisit4();" fullword ascii
    $s17 = "var winded =\"JVRFTVAl\".revisit4();" fullword ascii
    $s18 = "function hygiene(profession, weighted) {" fullword ascii
    $s19 = "var overdo = [surplice, algonquin,winded,  \"\"+\".\"+(\"feeds\",\"tally\",\"colon\",\"seller\",\"uzbekistan\",\"artisan\",\"hun" ascii
    $s20 = "coined\",\"audience\",\"worked\",\"jeremy\",\"jackie\",\"utils\",\"2.\")+\"XM\"+\"LH\"+\"TT\"+(\"pants\",\"flame\",\"dakota\",\"" ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}