rule sig_20160518_6676c1ed85aa1f0be4f20af9b6904683 {
  meta:
    description = "datamaliciousorder - file 20160518_6676c1ed85aa1f0be4f20af9b6904683.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e037f39a2a6dbc89140408e46af0165a53cb033e42cf0b4a58853e90a4f2dd6c"

  strings:
    $s1  = "var multiplication = [journalistic, grammatical,solid,  \"\"+\".\"+(\"divulge\",\"disorders\",\"stile\",\"nomination\",\"torpedo" ascii
    $s2  = "weasel = ((\"jingle\", \"disinherit\", \"mouthful\", \"favorite\", \"EqrraBpXe\") + \"psDfCQYj\").knocker2();" fullword ascii
    $s3  = "unwell(\"aHR0cDovLw==\".knocker4()+\"\\u0069\\u006B\\u006F\\u006E\\u0069\\u0063\\u0065\\u006B\\u002E\\u0077\\u007A\"+\"\\u002E" ascii
    $s4  = "String.prototype.knocker2 = function () {" fullword ascii
    $s5  = "String.prototype.knocker = function () {" fullword ascii
    $s6  = "String.prototype.knocker4 = function() {" fullword ascii
    $s7  = "mon\",\"panasonic\",\"melodrama\",\"guided\",\"drunk\",\"asking\",\"disks\",\"biodiversity\",\"SEOO\")+\"DB\"+(\"obviously\",\"s" ascii
    $s8  = "            ringtone[angular]((\"earrings\",\"bremen\",\"G\" + weasel) + (\"therell\",\"queens\",\"hygienic\",\"airport\",\"T\")" ascii
    $s9  = "            ringtone[angular]((\"earrings\",\"bremen\",\"G\" + weasel) + (\"therell\",\"queens\",\"hygienic\",\"airport\",\"T\")" ascii
    $s10 = "        physical[(friends + \"o\"+(\"conversion\",\"requirement\",\"laura\",\"chaldean\",\"warden\",\"basin\",\"wesley\",\"earth" ascii
    $s11 = "var journalistic = \"QWroumaniaN0aXZroumanialWE9iaroumaniamVjdA=roumania=\".knocker4();" fullword ascii
    $s12 = "constraint = this;" fullword ascii
    $s13 = "var ringtone = new chagrin(storehouse[0]);" fullword ascii
    $s14 = "intersection = \"_F2_\";" fullword ascii
    $s15 = "var mourner = new chagrin(storehouse[1]);" fullword ascii
    $s16 = "  knife = [];" fullword ascii
    $s17 = "function unwell(recipes, strand) {" fullword ascii
    $s18 = "angular = \"b3Blbg==\".knocker4();;" fullword ascii
    $s19 = "var solid =\"JVroumaniaRFTVroumaniaAl\".knocker4();" fullword ascii
    $s20 = "unwell(\"aHR0cDovLw==\".knocker4()+\"\\u0069\\u006B\\u006F\\u006E\\u0069\\u0063\\u0065\\u006B\\u002E\\u0077\\u007A\"+\"\\u002E" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}