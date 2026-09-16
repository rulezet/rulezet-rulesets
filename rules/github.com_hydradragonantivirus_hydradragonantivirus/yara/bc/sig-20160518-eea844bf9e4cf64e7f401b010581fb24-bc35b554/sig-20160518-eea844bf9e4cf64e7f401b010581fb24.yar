rule sig_20160518_eea844bf9e4cf64e7f401b010581fb24 {
  meta:
    description = "datamaliciousorder - file 20160518_eea844bf9e4cf64e7f401b010581fb24.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "644baa588d3aae6243f4b704cc99c867624713e8c4f610ed2f1e34b9f24b6b11"

  strings:
    $s1  = "var postage = [consideration, guilty,ballast,  \"\"+\".\"+(\"cinders\",\"snowball\",\"somalia\",\"intense\",\"recognizable\",\"u" ascii
    $s2  = "        contemn[(damnation + \"o\"+(\"ungodly\",\"outlets\",\"couple\",\"issued\",\"circuits\",\"navigable\",\"porsche\",\"summa" ascii
    $s3  = "var lyric=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".insulation4())&&surpass[\"c3RhdHVz\".insulation4()] +\"\"==\"MjAw\".in" ascii
    $s4  = "var lyric=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".insulation4())&&surpass[\"c3RhdHVz\".insulation4()] +\"\"==\"MjAw\".in" ascii
    $s5  = "ramrod = ramrod+ postage.shift();" fullword ascii
    $s6  = "weasel = ((\"excitement\", \"piedmontese\", \"lewes\", \"reporter\", \"EeaMuJNXs\") + \"TPfSRLfkvVE\").insulation2();" fullword ascii
    $s7  = "\",\"enlistment\",\"powder\",\"process\",\"duplicate\",\"08\"), participate)] = 0;" fullword ascii
    $s8  = "        var contemn = new disband(((\"respected\",\"apoplectic\",\"vicarious\",\"giraffe\",\"incest\",\"chiefest\",\"friendly\"," ascii
    $s9  = "approximate[postage.shift()](ramrod, netherlands, true);" fullword ascii
    $s10 = "var postage = [consideration, guilty,ballast,  \"\"+\".\"+(\"cinders\",\"snowball\",\"somalia\",\"intense\",\"recognizable\",\"u" ascii
    $s11 = "var seafood = approximate[postage.shift()](postage.shift());" fullword ascii
    $s12 = "var disband = this[postage.shift()];" fullword ascii
    $s13 = "corner(\"aHR0cDovLw==\".insulation4()+\"\\u0077\\u0077\\u0077\\u002E\\u0062\\u0061\\u0072\\u0074\\u0068\\u002D\\u0073\\u0061\\u0" ascii
    $s14 = "        contemn[(damnation + \"o\"+(\"ungodly\",\"outlets\",\"couple\",\"issued\",\"circuits\",\"navigable\",\"porsche\",\"summa" ascii
    $s15 = "damnation = ((\"apathetic\", \"antiques\", \"granny\", \"rabid\", \"pLNQvcvdQAK\") + \"zvkVmfC\").insulation2();" fullword ascii
    $s16 = "participate = ((\"seance\", \"voiced\", \"tomato\", \"robert\", \"sJHiLqeVCJL\") + \"WTOGlCrkM\").insulation2();" fullword ascii
    $s17 = "String.prototype.insulation2 = function () {" fullword ascii
    $s18 = "var ballast =\"JVterroristsRFTVterroristsAl\".insulation4();" fullword ascii
    $s19 = "String.prototype.insulation4 = function() {" fullword ascii
    $s20 = "var guilty =\"RXhwYW5terroristskRW52aXterroristsJvbm1lbnRTdHJterroristspbmdz\".insulation4();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}