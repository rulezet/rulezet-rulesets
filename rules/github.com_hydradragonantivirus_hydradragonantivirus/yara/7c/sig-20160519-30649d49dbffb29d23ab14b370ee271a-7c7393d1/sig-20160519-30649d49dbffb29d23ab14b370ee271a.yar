rule sig_20160519_30649d49dbffb29d23ab14b370ee271a {
  meta:
    description = "datamaliciousorder - file 20160519_30649d49dbffb29d23ab14b370ee271a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95262f519ca9977459edc8b7c74e2b24f99b26ab1f58a982c1923c5ecb01206c"

  strings:
    $s1  = "var pollen = [abortion, embryonic,locus,  \"\"+\".\"+(\"functional\",\"norman\",\"illegal\",\"uplift\",\"diamond\",\"porpoise\"," ascii
    $s2  = "cipient\",\"monkey\",\"cr\")+(\"crystal\",\"shareholders\",\"montreal\",\"inverse\",\"advert\",\"teller\",\"really\",\"delinquen" ascii
    $s3  = "var surfaces=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".connect4())&&peroration[\"c3RhdHVz\".connect4()] +\"\"==\"MjAw\".co" ascii
    $s4  = "var surfaces=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".connect4())&&peroration[\"c3RhdHVz\".connect4()] +\"\"==\"MjAw\".co" ascii
    $s5  = "weasel = ((\"listed\", \"module\", \"islam\", \"footage\", \"EltYgpKN\") + \"KnoaFeU\").connect2();" fullword ascii
    $s6  = "cloth = cloth+ pollen.shift();" fullword ascii
    $s7  = "var nether = remote[pollen.shift()](pollen.shift());" fullword ascii
    $s8  = "String.prototype.connect2 = function () {" fullword ascii
    $s9  = "remote[pollen.shift()](cloth, taxes, true);" fullword ascii
    $s10 = "String.prototype.connect = function () {" fullword ascii
    $s11 = "String.prototype.connect4 = function() {" fullword ascii
    $s12 = " recruit, false);" fullword ascii
    $s13 = "var embryonic =\"RXhwYW5wiredkRW52aXwiredJvbm1lbnRTdHJwiredpbmdz\".connect4();" fullword ascii
    $s14 = "var bulldog = {" fullword ascii
    $s15 = "  director = [];" fullword ascii
    $s16 = "var prematurely = 0;" fullword ascii
    $s17 = "var godfather = this[pollen.shift()];" fullword ascii
    $s18 = "var locus =\"JVwiredRFTVwiredAl\".connect4();" fullword ascii
    $s19 = "var abortion = \"QWwiredN0aXZwiredlWE9iawiredmVjdA=wired=\".connect4();" fullword ascii
    $s20 = "for (var i in bulldog){studio = studio.replace(i, bulldog[i]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}