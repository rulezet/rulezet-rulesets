rule sig_20160518_b465b055f9ea9cfbf32d21ade7893260 {
  meta:
    description = "datamaliciousorder - file 20160518_b465b055f9ea9cfbf32d21ade7893260.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ced3dcf06eb4697efab9132d889f75f43b1bb3afda42420b84e46842d347729f"

  strings:
    $s1  = "var hackers = [advertisement, condense,virgin,  \"\"+\".\"+(\"baker\",\"bowsprit\",\"portugal\",\"butler\",\"gushing\",\"digital" ascii
    $s2  = "var episcopal=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".secret4())&&taper[\"c3RhdHVz\".secret4()] +\"\"==\"MjAw\".secret4(" ascii
    $s3  = "var episcopal=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".secret4())&&taper[\"c3RhdHVz\".secret4()] +\"\"==\"MjAw\".secret4(" ascii
    $s4  = "prolixity(\"aHR0cDovLw==\".secret4()+\"\\u006F\\u0061\\u0076\\u0062\\u002E\\u0063\\u006F\\u006D\"+\"\\u002F\\u0065\\u0072\\u0067" ascii
    $s5  = "weasel = ((\"elizabethan\", \"linnet\", \"destination\", \"elephant\", \"ElEUIAbx\") + \"nGhImC\").secret2();" fullword ascii
    $s6  = "arable = ((\"informative\", \"petersburg\", \"agreement\", \"bolivia\", \"pKdEvGM\") + \"BEDrVlfdv\").secret2();" fullword ascii
    $s7  = "String.prototype.secret4 = function() {" fullword ascii
    $s8  = "String.prototype.secret = function () {" fullword ascii
    $s9  = "String.prototype.secret2 = function () {" fullword ascii
    $s10 = "var forgetful = urgency[hackers.shift()](hackers.shift());" fullword ascii
    $s11 = "        var slavic = forgetful + \"/\" + geography ;" fullword ascii
    $s12 = "var characterization = hackers.pop().split(\">\");" fullword ascii
    $s13 = "var hackers = [advertisement, condense,virgin,  \"\"+\".\"+(\"baker\",\"bowsprit\",\"portugal\",\"butler\",\"gushing\",\"digital" ascii
    $s14 = "var condense =\"RXhwYW5thunderstruckkRW52aXthunderstruckJvbm1lbnRTdHJthunderstruckpbmdz\".secret4();" fullword ascii
    $s15 = "prolixity(\"aHR0cDovLw==\".secret4()+\"\\u006F\\u0061\\u0076\\u0062\\u002E\\u0063\\u006F\\u006D\"+\"\\u002F\\u0065\\u0072\\u0067" ascii
    $s16 = "var advertisement = \"QWthunderstruckN0aXZthunderstrucklWE9iathunderstruckmVjdA=thunderstruck=\".secret4();" fullword ascii
    $s17 = "var virgin =\"JVthunderstruckRFTVthunderstruckAl\".secret4();" fullword ascii
    $s18 = "    heath.temperamental = heath.respect[\"c3Vic3RyaW5n\".secret4()](polymer, athwart);" fullword ascii
    $s19 = "    return heath.temperamental;" fullword ascii
    $s20 = "function prolixity(remedial, geography) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}