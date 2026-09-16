rule sig_20160517_c949025bc88c805e3877174375569f20 {
  meta:
    description = "datamaliciousorder - file 20160517_c949025bc88c805e3877174375569f20.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac8be8c4cfab57e20bf04e5c8342c2269901de7d745e7f5e76522e02c4654e05"

  strings:
    $s1  = "fiber = ((\"plaudits\", \"cherry\", \"strictly\", \"redhead\", \"skvlmJEvRt\") + \"ybOBfNA\").austin2();" fullword ascii
    $s2  = "var ensures=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".austin4())&&debauchery[\"c3RhdHVz\".austin4()] +\"\"==\"MjAw\".austi" ascii
    $s3  = "nre\",\"developing\",\"stickers\",\"price\",\"ip\")+\"t:\"+(\"dispersing\",\"experienced\",\"clearly\",\"smoky\",\"tainted\",\"m" ascii
    $s4  = "var ensures=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".austin4())&&debauchery[\"c3RhdHVz\".austin4()] +\"\"==\"MjAw\".austi" ascii
    $s5  = "weasel = ((\"bikini\", \"writing\", \"salem\", \"richie\", \"ETglivJhB\") + \"ilmpQhPrjAf\").austin2();" fullword ascii
    $s6  = "firewood(\"aHR0cDovLw==\".austin4()+\"\\u0065\\u0061\\u0073\\u0079\\u0073\\u0075\\u0070\\u0070\\u006F\\u0072\\u0074\"+\"\\u002E" ascii
    $s7  = "however = ((\"reform\", \"pharmacies\", \"transmitting\", \"tigris\", \"pRowizCdCHji\") + \"BoaNjPp\").austin2();" fullword ascii
    $s8  = "flurry = flurry+ cleanly.shift();" fullword ascii
    $s9  = "String.prototype.austin = function () {" fullword ascii
    $s10 = "var ready = sneeze[cleanly.shift()](cleanly.shift());" fullword ascii
    $s11 = "String.prototype.austin2 = function () {" fullword ascii
    $s12 = "Rt\"+(\"narrate\",\"linseed\",\"precise\",\"compression\",\"pregnant\",\"powerseller\",\"bookmarks\",\"ri\")+\"ng\").replace(\"R" ascii
    $s13 = "String.prototype.austin4 = function() {" fullword ascii
    $s14 = "        var flurry = ready + \"/\" + amiably ;" fullword ascii
    $s15 = "var cleanly = [withering, limited,abroad,  \"\"+\".\"+(\"intensive\",\"christina\",\"whore\",\"rheumatism\",\"obligations\",\"ri" ascii
    $s16 = "var bosnia = this[cleanly.shift()];" fullword ascii
    $s17 = "var killing = {" fullword ascii
    $s18 = "var abroad =\"JVaffectedRFTVaffectedAl\".austin4();" fullword ascii
    $s19 = "transitory = this;" fullword ascii
    $s20 = "var debauchery = new bosnia(marche[0]);" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}