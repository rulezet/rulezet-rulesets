rule sig_20160518_b4360d68ec3b04d0d20f6cfc868a4d17 {
  meta:
    description = "datamaliciousorder - file 20160518_b4360d68ec3b04d0d20f6cfc868a4d17.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cc2c9f6a944e6a07593a5726f2bf1ac80401b8c649cea240802395ba53e5681"

  strings:
    $s1  = "var create = [mediawiki, gunwale,electrical,  \"\"+\".\"+(\"imagery\",\"guinea\",\"tuition\",\"globular\",\"bivouac\",\"glasgow" ascii
    $s2  = "var amalgamation=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".abbeys4())&&arian[\"c3RhdHVz\".abbeys4()] +\"\"==\"MjAw\".abbey" ascii
    $s3  = "var create = [mediawiki, gunwale,electrical,  \"\"+\".\"+(\"imagery\",\"guinea\",\"tuition\",\"globular\",\"bivouac\",\"glasgow" ascii
    $s4  = "  compassionate = [];" fullword ascii
    $s5  = "      compassionate[ i ] = -1;" fullword ascii
    $s6  = "technological = technological+ create.shift();" fullword ascii
    $s7  = "            arian[talented]((\"recognizable\",\"nebulous\",\"G\" + weasel) + (\"matrix\",\"sepulchre\",\"accessed\",\"expostulat" ascii
    $s8  = "reinstate(\"aHR0cDovLw==\".abbeys4()+\"\\u0066\\u0065\\u0065\\u0064\\u0063\\u006F\\u006E\\u0073\\u0075\\u006D\\u0065\\u0072\\u00" ascii
    $s9  = "weasel = ((\"monopolize\", \"melissa\", \"round\", \"reticence\", \"EWONEsiQmG\") + \"WtJMwgmd\").abbeys2();" fullword ascii
    $s10 = "serenade = ((\"magnetic\", \"weighted\", \"worry\", \"kinsmen\", \"sicdQBUF\") + \"IqyGVABRdjH\").abbeys2();" fullword ascii
    $s11 = "            arian[talented]((\"recognizable\",\"nebulous\",\"G\" + weasel) + (\"matrix\",\"sepulchre\",\"accessed\",\"expostulat" ascii
    $s12 = "String.prototype.abbeys2 = function () {" fullword ascii
    $s13 = "String.prototype.abbeys4 = function() {" fullword ascii
    $s14 = "String.prototype.abbeys = function () {" fullword ascii
    $s15 = "        insular[(pollyanna + \"o\"+(\"chide\",\"fortyfour\",\"disillusion\",\"machinery\",\"separate\",\"conclude\",\"completion" ascii
    $s16 = "    c4 = compassionate[c4];" fullword ascii
    $s17 = "dialects[create.shift()](technological, thinkpad, true);" fullword ascii
    $s18 = "    compassionate[ glasses.charCodeAt( i ) ] = i;" fullword ascii
    $s19 = "    if ( compassionate[ i ] === undefined )" fullword ascii
    $s20 = "    c3 = compassionate[c3];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}