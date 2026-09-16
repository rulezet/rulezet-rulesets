rule sig_20160518_e117add40f07c184e5ece5a3c5847ec4 {
  meta:
    description = "datamaliciousorder - file 20160518_e117add40f07c184e5ece5a3c5847ec4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d35e469e606836d29d417e2cf6ac075851c15c71c9c201411bc9720636c15a4e"

  strings:
    $s1  = "weasel = ((\"genealogy\", \"delirious\", \"indexed\", \"chaotic\", \"EOyuEuwgXHhJ\") + \"fXcReryMq\").ellen2();" fullword ascii
    $s2  = "var hierarchy = [formulae, physician,photographic,  \"\"+\".\"+(\"partakes\",\"entire\",\"peppermint\",\"compendium\",\"vestige" ascii
    $s3  = "\"readers\",\"hearse\",\"compete\",\"myanmar\",\"mozambique\",\"suggested\",\"plastered\",\"8i\")+\"tion\").replace(\"0\"+(\"del" ascii
    $s4  = "        foremen[(troubleshooting + \"o\"+(\"exterminate\",\"voyager\",\"trend\",\"coins\",\"learners\",\"tutelary\",\"volume\"," ascii
    $s5  = "stunt(\"aHR0cDovLw==\".ellen4()+\"\\u0077\\u0077\\u0077\\u002E\\u0062\\u0061\\u0072\\u0073\\u0072\\u0061\\u0063\\u0069\\u006E\"+" ascii
    $s6  = "arise = arise+ hierarchy.shift();" fullword ascii
    $s7  = "sensed = ((\"instantaneous\", \"eaves\", \"approximately\", \"emanuel\", \"slVDbJPY\") + \"PpXPvc\").ellen2();" fullword ascii
    $s8  = "var truism = hierarchy.pop().split(\">\");" fullword ascii
    $s9  = "String.prototype.ellen2 = function () {" fullword ascii
    $s10 = "String.prototype.ellen4 = function() {" fullword ascii
    $s11 = "var hierarchy = [formulae, physician,photographic,  \"\"+\".\"+(\"partakes\",\"entire\",\"peppermint\",\"compendium\",\"vestige" ascii
    $s12 = "String.prototype.ellen = function () {" fullword ascii
    $s13 = "crate = this;" fullword ascii
    $s14 = "  course = [];" fullword ascii
    $s15 = "var sterling = new thinking(truism[1]);" fullword ascii
    $s16 = "var displayed = sterling[hierarchy.shift()](hierarchy.shift());" fullword ascii
    $s17 = "var thinking = this[hierarchy.shift()];" fullword ascii
    $s18 = "var physician =\"RXhwYW5argumentativekRW52aXargumentativeJvbm1lbnRTdHJargumentativepbmdz\".ellen4();" fullword ascii
    $s19 = "var cognitive = 0;" fullword ascii
    $s20 = "for (var i in tartarus){crate = crate.replace(i, tartarus[i]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}