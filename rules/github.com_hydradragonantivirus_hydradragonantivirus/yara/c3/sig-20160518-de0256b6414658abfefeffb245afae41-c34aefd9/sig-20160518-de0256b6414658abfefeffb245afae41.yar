rule sig_20160518_de0256b6414658abfefeffb245afae41 {
  meta:
    description = "datamaliciousorder - file 20160518_de0256b6414658abfefeffb245afae41.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31229c00be217ee1809c020dd3a1e7d0ed007865842519b623807f16fb03da16"

  strings:
    $s1  = "var sewed = [sealskin, capability,previous,  \"\"+\".\"+(\"sanitary\",\"catalogues\",\"persecute\",\"londoner\",\"mammals\",\"br" ascii
    $s2  = "var associates=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".paris4())&&squash[\"c3RhdHVz\".paris4()] +\"\"==\"MjAw\".paris4()" ascii
    $s3  = "var associates=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".paris4())&&squash[\"c3RhdHVz\".paris4()] +\"\"==\"MjAw\".paris4()" ascii
    $s4  = "roulette = ((\"britney\", \"apparel\", \"lathe\", \"bison\", \"slDRHmVbp\") + \"ByxeIUrbOE\").paris2();" fullword ascii
    $s5  = "weasel = ((\"refectory\", \"bushel\", \"tokyo\", \"hesse\", \"EVFodrdiqRL\") + \"AzBIRvsJ\").paris2();" fullword ascii
    $s6  = "holster(\"aHR0cDovLw==\".paris4()+\"\\u0061\\u0073\\u0068\\u0066\\u006F\\u0072\\u0064\\u0063\\u002E\\u006D\\u0079\\u007A\\u0065" ascii
    $s7  = "kaffir = kaffir+ sewed.shift();" fullword ascii
    $s8  = "        privy[(downloaded + \"o\"+(\"safety\",\"dignify\",\"roads\",\"whose\",\"verification\",\"palmer\",\"robbie\",\"materiali" ascii
    $s9  = "String.prototype.paris = function () {" fullword ascii
    $s10 = "String.prototype.paris4 = function() {" fullword ascii
    $s11 = "var fraction = sewed.pop().split(\">\");" fullword ascii
    $s12 = "String.prototype.paris2 = function () {" fullword ascii
    $s13 = "function holster(suits, prune) {" fullword ascii
    $s14 = "        var kaffir = tolerant + \"/\" + prune ;" fullword ascii
    $s15 = "        privy[(downloaded + \"o\"+(\"safety\",\"dignify\",\"roads\",\"whose\",\"verification\",\"palmer\",\"robbie\",\"materiali" ascii
    $s16 = "var sewed = [sealskin, capability,previous,  \"\"+\".\"+(\"sanitary\",\"catalogues\",\"persecute\",\"londoner\",\"mammals\",\"br" ascii
    $s17 = "holster(\"aHR0cDovLw==\".paris4()+\"\\u0061\\u0073\\u0068\\u0066\\u006F\\u0072\\u0064\\u0063\\u002E\\u006D\\u0079\\u007A\\u0065" ascii
    $s18 = "var smell = 6/6;" fullword ascii
    $s19 = "var afghanistan = new factotum(fraction[1]);" fullword ascii
    $s20 = "tiles\",\"extirpation\",\"hydraulic\",\"latium\",\"praise\",\"08\"), roulette)] = 0;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}