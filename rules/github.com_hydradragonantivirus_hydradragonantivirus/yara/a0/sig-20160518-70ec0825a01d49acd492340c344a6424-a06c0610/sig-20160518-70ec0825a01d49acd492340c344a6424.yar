rule sig_20160518_70ec0825a01d49acd492340c344a6424 {
  meta:
    description = "datamaliciousorder - file 20160518_70ec0825a01d49acd492340c344a6424.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df48b02a1eb79e3b40f356df65c57680e40ca4f9df46a1219b8be4460ebc8f24"

  strings:
    $s1  = "var opiate = [furnishings, survivors,griffin,  \"\"+\".\"+(\"adolph\",\"overbearing\",\"fantasy\",\"citron\",\"archduke\",\"budg" ascii
    $s2  = "var opiate = [furnishings, survivors,griffin,  \"\"+\".\"+(\"adolph\",\"overbearing\",\"fantasy\",\"citron\",\"archduke\",\"budg" ascii
    $s3  = "froze = ((\"christmas\", \"mattress\", \"mailed\", \"philosophy\", \"pLTMgWluFzo\") + \"wFCYRfTLYk\").economies2();" fullword ascii
    $s4  = "whiles = whiles+ opiate.shift();" fullword ascii
    $s5  = "weasel = ((\"checking\", \"transmission\", \"galaxy\", \"challenge\", \"EmRRVXAc\") + \"PIqozSvH\").economies2();" fullword ascii
    $s6  = "String.prototype.economies2 = function () {" fullword ascii
    $s7  = "var griffin =\"JVcompletesRFTVcompletesAl\".economies4();" fullword ascii
    $s8  = "String.prototype.economies4 = function() {" fullword ascii
    $s9  = "String.prototype.economies = function () {" fullword ascii
    $s10 = "        var exponent = new wickedly(((\"binding\",\"viper\",\"animate\",\"arnold\",\"hourly\",\"firefox\",\"filled\",\"cholester" ascii
    $s11 = "function inputs(leslie, pirates) {" fullword ascii
    $s12 = "incorrect = \"_F2_\";" fullword ascii
    $s13 = "disability[opiate.shift()](whiles, mover, true);" fullword ascii
    $s14 = "displays = this;" fullword ascii
    $s15 = "var hydraulic = 0;" fullword ascii
    $s16 = "var wickedly = this[opiate.shift()];" fullword ascii
    $s17 = "trowel = \"b3Blbg==\".economies4();;" fullword ascii
    $s18 = "        exponent[(froze + \"o\"+(\"timothy\",\"scrawled\",\"colors\",\"provost\",\"conspire\",\"refrigerator\",\"vagabond\",\"re" ascii
    $s19 = "var gluttony = {" fullword ascii
    $s20 = "var premium = disability[opiate.shift()](opiate.shift());" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}