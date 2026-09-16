rule sig_20160518_4ec3d4ce62bbdaa91554c0c47c49fe47 {
  meta:
    description = "datamaliciousorder - file 20160518_4ec3d4ce62bbdaa91554c0c47c49fe47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "246414ae9b7edd300be06f8cc60d4bbc609f0a1310707a9ed4acccd2cf1bcf11"

  strings:
    $s1  = "var seasoning = [device, angelus,invention,  \"\"+\".\"+(\"vehicle\",\"forecasts\",\"credulous\",\"goodfellowship\",\"rally\",\"" ascii
    $s2  = "\"frontal\",\"processes\",\"managed\",\"preceptor\",\"intensity\",\"trusts\",\"blades\",\"reserves\",\"SEOO\")+\"DB\"+(\"chink\"" ascii
    $s3  = "haired = ((\"pittance\", \"strong\", \"biology\", \"ungodly\", \"pFXirbT\") + \"qGttXqXTn\").fernando2();" fullword ascii
    $s4  = "income = income+ seasoning.shift();" fullword ascii
    $s5  = "weasel = ((\"unconnected\", \"harpsichord\", \"retrieve\", \"worcester\", \"EdRUSWb\") + \"dCpNsNJ\").fernando2();" fullword ascii
    $s6  = "currant(\"aHR0cDovLw==\".fernando4()+\"\\u0074\\u0068\\u0065\\u006D\\u0061\\u0074\\u0068\\u0077\\u0065\\u0062\\u0073\\u0069\\u00" ascii
    $s7  = "for (var i in incompatible){forum = forum.replace(i, incompatible[i]);}" fullword ascii
    $s8  = "var incompatible = {" fullword ascii
    $s9  = "String.prototype.fernando4 = function() {" fullword ascii
    $s10 = "String.prototype.fernando = function () {" fullword ascii
    $s11 = "String.prototype.fernando2 = function () {" fullword ascii
    $s12 = "var pushing = seasoning.pop().split(\">\");" fullword ascii
    $s13 = "derisively[seasoning.shift()](income, russian, true);" fullword ascii
    $s14 = "        oratorical[(haired + \"o\"+(\"talented\",\"chills\",\"untamed\",\"foamy\",\"batman\",\"intake\",\"resistance\",\"dates\"" ascii
    $s15 = "        var oratorical = new casual(((\"listings\",\"deter\",\"fiendish\",\"testing\",\"items\",\"tightening\",\"leavings\",\"la" ascii
    $s16 = "var middleclass=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".fernando4())&&intake[\"c3RhdHVz\".fernando4()] +\"\"==\"MjAw\".f" ascii
    $s17 = "        var income = lovely + \"/\" + tiber ;" fullword ascii
    $s18 = "var middleclass=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".fernando4())&&intake[\"c3RhdHVz\".fernando4()] +\"\"==\"MjAw\".f" ascii
    $s19 = "var device = \"QWweedyN0aXZweedylWE9iaweedymVjdA=weedy=\".fernando4();" fullword ascii
    $s20 = "var colored = 0;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}