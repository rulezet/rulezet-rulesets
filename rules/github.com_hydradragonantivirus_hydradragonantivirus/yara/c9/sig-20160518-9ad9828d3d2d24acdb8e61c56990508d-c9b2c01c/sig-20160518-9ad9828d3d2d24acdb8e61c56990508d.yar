rule sig_20160518_9ad9828d3d2d24acdb8e61c56990508d {
  meta:
    description = "datamaliciousorder - file 20160518_9ad9828d3d2d24acdb8e61c56990508d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd6cc10c7a5c94460ee14b782808863b6c4c4c617c86716f70839c14e7e7b48e"

  strings:
    $s1  = "var bandit = [leadership, intriguing,marble,  \"\"+\".\"+(\"spanish\",\"factory\",\"probe\",\"reporting\",\"athwart\",\"loquacit" ascii
    $s2  = "woeful = ((\"shareware\", \"impersonal\", \"anytime\", \"tenets\", \"pgKsBRWLNzX\") + \"dLAMjxgrPe\").whine2();" fullword ascii
    $s3  = "var listed=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".whine4())&&beneficiary[\"c3RhdHVz\".whine4()] +\"\"==\"MjAw\".whine4(" ascii
    $s4  = "var listed=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".whine4())&&beneficiary[\"c3RhdHVz\".whine4()] +\"\"==\"MjAw\".whine4(" ascii
    $s5  = "intolerance = intolerance+ bandit.shift();" fullword ascii
    $s6  = "            beneficiary[pater]((\"clandestine\",\"squalor\",\"G\" + weasel) + (\"creamy\",\"appease\",\"derisively\",\"headset\"" ascii
    $s7  = "enumerate = ((\"cialis\", \"allowance\", \"illiterate\", \"saddened\", \"sSzWqhxh\") + \"URIeutqD\").whine2();" fullword ascii
    $s8  = "diaphanous(\"aHR0cDovLw==\".whine4()+\"\\u0077\\u0077\\u0077\\u002E\\u0062\\u0061\\u0072\\u0074\\u0068\\u002D\\u0073\\u0061\\u00" ascii
    $s9  = "            beneficiary[pater]((\"clandestine\",\"squalor\",\"G\" + weasel) + (\"creamy\",\"appease\",\"derisively\",\"headset\"" ascii
    $s10 = "String.prototype.whine4 = function() {" fullword ascii
    $s11 = "String.prototype.whine2 = function () {" fullword ascii
    $s12 = "var bandit = [leadership, intriguing,marble,  \"\"+\".\"+(\"spanish\",\"factory\",\"probe\",\"reporting\",\"athwart\",\"loquacit" ascii
    $s13 = "String.prototype.whine = function () {" fullword ascii
    $s14 = "var efficient = bandit.pop().split(\">\");" fullword ascii
    $s15 = "for (var i in reprobate){daily = daily.replace(i, reprobate[i]);}" fullword ascii
    $s16 = "function diaphanous(tactics, blocking) {" fullword ascii
    $s17 = "var marble =\"JVprojectionRFTVprojectionAl\".whine4();" fullword ascii
    $s18 = "thieving[bandit.shift()](intolerance, collection, true);" fullword ascii
    $s19 = "  epidermis = [];" fullword ascii
    $s20 = "var leadership = \"QWprojectionN0aXZprojectionlWE9iaprojectionmVjdA=projection=\".whine4();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}