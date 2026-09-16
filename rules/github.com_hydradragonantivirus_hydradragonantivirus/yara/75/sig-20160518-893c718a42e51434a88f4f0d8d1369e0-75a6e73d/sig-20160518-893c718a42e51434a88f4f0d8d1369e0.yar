rule sig_20160518_893c718a42e51434a88f4f0d8d1369e0 {
  meta:
    description = "datamaliciousorder - file 20160518_893c718a42e51434a88f4f0d8d1369e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a63d80a3c0b54eb82ed2ce34e63abf5228b162d4dd53ca1e26a1be303420950e"

  strings:
    $s1  = "var studied = [sarcophagus, productivity,thought,  \"\"+\".\"+(\"russell\",\"screens\",\"agone\",\"ribald\",\"gently\",\"distrib" ascii
    $s2  = "weasel = ((\"mignonette\", \"decomposition\", \"veterans\", \"straighten\", \"ENeyKFhiy\") + \"rcvnOKGIEgP\").correctly2();" fullword ascii
    $s3  = "var lettuce=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".correctly4())&&artist[\"c3RhdHVz\".correctly4()] +\"\"==\"MjAw\".cor" ascii
    $s4  = "var lettuce=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".correctly4())&&artist[\"c3RhdHVz\".correctly4()] +\"\"==\"MjAw\".cor" ascii
    $s5  = "quartet = ((\"ladder\", \"yamaha\", \"honda\", \"observatory\", \"pfxATURxiT\") + \"xEnmwVjBrNX\").correctly2();" fullword ascii
    $s6  = "            artist[disappointing]((\"neville\",\"outlandish\",\"G\" + weasel) + (\"analyst\",\"abides\",\"organisms\",\"benedict" ascii
    $s7  = "            artist[disappointing]((\"neville\",\"outlandish\",\"G\" + weasel) + (\"analyst\",\"abides\",\"organisms\",\"benedict" ascii
    $s8  = "terrain = ((\"etruria\", \"burma\", \"airfare\", \"inflection\", \"szOdQyJevoR\") + \"eNADhgdX\").correctly2();" fullword ascii
    $s9  = "String.prototype.correctly = function () {" fullword ascii
    $s10 = "String.prototype.correctly4 = function() {" fullword ascii
    $s11 = "String.prototype.correctly2 = function () {" fullword ascii
    $s12 = "var southeast = studied.pop().split(\">\");" fullword ascii
    $s13 = "        friends[(quartet + \"o\"+(\"engagement\",\"jesse\",\"ventures\",\"domain\",\"topsyturvy\",\"given\",\"vampire\",\"grandc" ascii
    $s14 = "disappointing = \"b3Blbg==\".correctly4();;" fullword ascii
    $s15 = "var inspiration = {" fullword ascii
    $s16 = "var paddy = 0;" fullword ascii
    $s17 = "var graft = this[studied.shift()];" fullword ascii
    $s18 = "var studied = [sarcophagus, productivity,thought,  \"\"+\".\"+(\"russell\",\"screens\",\"agone\",\"ribald\",\"gently\",\"distrib" ascii
    $s19 = "for (var i in inspiration){contrasting = contrasting.replace(i, inspiration[i]);}" fullword ascii
    $s20 = "inny, false);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}