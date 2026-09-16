rule sig_20160518_44a9f38601a7c89249cafe00f9ecc192 {
  meta:
    description = "datamaliciousorder - file 20160518_44a9f38601a7c89249cafe00f9ecc192.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "429b7b345fa031717cdab1efde1567247dc560d9b375a691259b6524efee269c"

  strings:
    $s1  = "var wildcat = [dormitory, knitting,laureate,  \"\"+\".\"+(\"epidermis\",\"eightyfive\",\"subsequently\",\"pursuant\",\"vessels\"" ascii
    $s2  = "weasel = ((\"things\", \"committed\", \"philips\", \"router\", \"EXrAreCEq\") + \"AQoRezPr\").cooler2();" fullword ascii
    $s3  = "        deputation[(dolphin + \"o\"+(\"meddling\",\"fallow\",\"gambler\",\"teacher\",\"slander\",\"conscript\",\"florist\",\"alb" ascii
    $s4  = "        deputation[(dolphin + \"o\"+(\"meddling\",\"fallow\",\"gambler\",\"teacher\",\"slander\",\"conscript\",\"florist\",\"alb" ascii
    $s5  = "    roland[kinase + (\"impromptu\",\"subheading\",\"end\")]();" fullword ascii
    $s6  = "dolphin = ((\"settled\", \"montenegro\", \"fermented\", \"websites\", \"pUBxXcnqsl\") + \"DtJNCqF\").cooler2();" fullword ascii
    $s7  = "String.prototype.cooler2 = function () {" fullword ascii
    $s8  = "String.prototype.cooler4 = function() {" fullword ascii
    $s9  = "String.prototype.cooler = function () {" fullword ascii
    $s10 = "var wildcat = [dormitory, knitting,laureate,  \"\"+\".\"+(\"epidermis\",\"eightyfive\",\"subsequently\",\"pursuant\",\"vessels\"" ascii
    $s11 = "function miles(undergraduate, erosion) {" fullword ascii
    $s12 = "var dormitory = \"QWirelandN0aXZirelandlWE9iairelandmVjdA=ireland=\".cooler4();" fullword ascii
    $s13 = "kinase = ((\"offing\", \"respond\", \"toward\", \"walnut\", \"siVBdycaKMY\") + \"IJnXiVn\").cooler2();" fullword ascii
    $s14 = "var boxer = 6/6;" fullword ascii
    $s15 = "reconsider = \"b3Blbg==\".cooler4();;" fullword ascii
    $s16 = "tower = tower+ wildcat.shift();" fullword ascii
    $s17 = "var accordingly = 0;" fullword ascii
    $s18 = "  interpose = [];" fullword ascii
    $s19 = "for (var i in struct){working = working.replace(i, struct[i]);}" fullword ascii
    $s20 = "var knitting =\"RXhwYW5irelandkRW52aXirelandJvbm1lbnRTdHJirelandpbmdz\".cooler4();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}