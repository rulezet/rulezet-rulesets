rule sig_20160518_8058b361cd5f6842a90562ca058c9bd2 {
  meta:
    description = "datamaliciousorder - file 20160518_8058b361cd5f6842a90562ca058c9bd2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ed9052b69e3a48bb2a4b4347ee6868bbc11c44f1382f60f4a965725d38ac5a4"

  strings:
    $s1  = "var prescription = [guided, ambiguity,shear,  \"\"+\".\"+(\"congo\",\"harley\",\"busty\",\"corset\",\"structural\",\"acceded\"," ascii
    $s2  = "construct\",\"tremendous\",\"satisfied\",\"manifesting\",\"temporarily\",\"P>\")+\"WU\"+(\"football\",\"hardheaded\",\"noncommis" ascii
    $s3  = "var grown = prescription.pop().split(\">\");" fullword ascii
    $s4  = "var disarm=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".revenge4())&&strike[\"c3RhdHVz\".revenge4()] +\"\"==\"MjAw\".revenge4" ascii
    $s5  = "var barometer = this[prescription.shift()];" fullword ascii
    $s6  = "var disarm=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".revenge4())&&strike[\"c3RhdHVz\".revenge4()] +\"\"==\"MjAw\".revenge4" ascii
    $s7  = "var prescription = [guided, ambiguity,shear,  \"\"+\".\"+(\"congo\",\"harley\",\"busty\",\"corset\",\"structural\",\"acceded\"," ascii
    $s8  = "theories[prescription.shift()](fermented, grove, true);" fullword ascii
    $s9  = "    target.narrator = target.charm[\"c3Vic3RyaW5n\".revenge4()](module, grove);" fullword ascii
    $s10 = "    return target.narrator;" fullword ascii
    $s11 = "weasel = ((\"result\", \"playground\", \"mambo\", \"reservation\", \"ETVqIDMaQ\") + \"TSmMQGlqH\").revenge2();" fullword ascii
    $s12 = "coercion = ((\"offshoot\", \"production\", \"rebate\", \"inducing\", \"sisscfieru\") + \"GNLFCQhy\").revenge2();" fullword ascii
    $s13 = "String.prototype.revenge = function () {" fullword ascii
    $s14 = "String.prototype.revenge4 = function() {" fullword ascii
    $s15 = "String.prototype.revenge2 = function () {" fullword ascii
    $s16 = "            strike[photographer]((\"spouse\",\"regent\",\"G\" + weasel) + (\"liberating\",\"known\",\"thankfulness\",\"commerce" ascii
    $s17 = "            strike[photographer]((\"spouse\",\"regent\",\"G\" + weasel) + (\"liberating\",\"known\",\"thankfulness\",\"commerce" ascii
    $s18 = "ization\",\"surpass\",\"capacity\",\"humorously\",\"cr\")+(\"textbooks\",\"phalanx\",\"cayman\",\"hamlet\",\"global\",\"comprise" ascii
    $s19 = "\"china\",\"arbiter\",\"monty\",\"peremptory\",\"catalogs\",\"08\"), coercion)] = 0;" fullword ascii
    $s20 = "rs, false);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}