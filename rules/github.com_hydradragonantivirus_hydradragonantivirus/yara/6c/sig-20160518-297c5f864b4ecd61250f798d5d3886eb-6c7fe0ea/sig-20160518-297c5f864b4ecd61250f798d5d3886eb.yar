rule sig_20160518_297c5f864b4ecd61250f798d5d3886eb {
  meta:
    description = "datamaliciousorder - file 20160518_297c5f864b4ecd61250f798d5d3886eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d23cb9c619ce38cb54f37631f819ad08ebd4f134eee5e59b5c71b286586473e8"

  strings:
    $s1  = "var seafood = [arcade, ashley,industrial,  \"\"+\".\"+(\"factitious\",\"physiological\",\"hands\",\"existing\",\"portuguese\",\"" ascii
    $s2  = "coincident(\"aHR0cDovLw==\".process4()+\"\\u006E\\u006F\\u006C\\u0077\\u006F\\u006F\\u0064\\u006C\\u0061\\u006E\\u0064\"+\"\\u00" ascii
    $s3  = "weasel = ((\"confronts\", \"named\", \"quince\", \"buttocks\", \"EjwRSBG\") + \"rUWKJRb\").process2();" fullword ascii
    $s4  = "String.prototype.process4 = function() {" fullword ascii
    $s5  = "String.prototype.process2 = function () {" fullword ascii
    $s6  = "String.prototype.process = function () {" fullword ascii
    $s7  = "viscount = \"b3Blbg==\".process4();;" fullword ascii
    $s8  = "instructor = ((\"displaying\", \"nails\", \"cartoon\", \"antediluvian\", \"seBKhzSl\") + \"yIXOrmvKy\").process2();" fullword ascii
    $s9  = "coincident(\"aHR0cDovLw==\".process4()+\"\\u006E\\u006F\\u006C\\u0077\\u006F\\u006F\\u0064\\u006C\\u0061\\u006E\\u0064\"+\"\\u00" ascii
    $s10 = "var industrial =\"JVimitatorRFTVimitatorAl\".process4();" fullword ascii
    $s11 = "var arcade = \"QWimitatorN0aXZimitatorlWE9iaimitatormVjdA=imitator=\".process4();" fullword ascii
    $s12 = "evade = evade+ seafood.shift();" fullword ascii
    $s13 = "var seafood = [arcade, ashley,industrial,  \"\"+\".\"+(\"factitious\",\"physiological\",\"hands\",\"existing\",\"portuguese\",\"" ascii
    $s14 = "        christianity[(larger + \"o\"+(\"quell\",\"diable\",\"pueblo\",\"spent\",\"kitchen\",\"resolution\",\"deepen\",\"facilita" ascii
    $s15 = "var fault = seafood.pop().split(\">\");" fullword ascii
    $s16 = "    unconcerned.shameless = unconcerned.candor[\"c3Vic3RyaW5n\".process4()](basque, magnetic);" fullword ascii
    $s17 = "        var evade = augur + \"/\" + grouping ;" fullword ascii
    $s18 = "        var christianity = new fitness(((\"demur\",\"preparing\",\"erroneously\",\"abomination\",\"flashing\",\"easter\",\"clive" ascii
    $s19 = "directory[seafood.shift()](evade, magnetic, true);" fullword ascii
    $s20 = "function coincident(transform, grouping) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}