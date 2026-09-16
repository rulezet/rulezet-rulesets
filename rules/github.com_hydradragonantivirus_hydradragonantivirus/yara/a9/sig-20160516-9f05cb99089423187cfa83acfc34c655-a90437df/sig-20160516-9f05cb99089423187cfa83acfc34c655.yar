rule sig_20160516_9f05cb99089423187cfa83acfc34c655 {
  meta:
    description = "datamaliciousorder - file 20160516_9f05cb99089423187cfa83acfc34c655.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f53a03d54b589974410a1c80cf724c7dd37316f10c7629fed41e54793e1f8888"

  strings:
    $s1  = "        jewellery[(fashion + \"o\"+(\"transcend\",\"creativity\",\"savings\",\"chisel\",\"trifled\",\"raises\",\"findlaw\",\"pro" ascii
    $s2  = "fashion = ((\"fender\", \"portrayal\", \"shallows\", \"wizard\", \"phEpqGAbqMtg\") + \"SMmgSJwQNs\").veteran2();" fullword ascii
    $s3  = "\"lounge\",\"antediluvian\",\"taciturnity\",\"ahead\",\"08\"), kingly)] = 0;" fullword ascii
    $s4  = "congestion(\"aHR0cDovLw==\".veteran4()+\"\\u0073\\u0074\\u0072\\u0073\\u0074\\u0075\\u0064\\u0069\\u006F\\u002E\"+\"\\u0070\\u00" ascii
    $s5  = "var implicit = [validity, traveller,enlightenment,  \"\"+\".\"+(\"britain\",\"holders\",\"distraught\",\"stack\",\"inhale\",\"re" ascii
    $s6  = "weasel = ((\"airplane\", \"nudity\", \"skylight\", \"stimulation\", \"EoInyVoLUNf\") + \"zlweJv\").veteran2();" fullword ascii
    $s7  = "kingly = ((\"grenada\", \"nipples\", \"chafe\", \"orthography\", \"sGdiELEQ\") + \"aQsBPbjop\").veteran2();" fullword ascii
    $s8  = "String.prototype.veteran = function () {" fullword ascii
    $s9  = "String.prototype.veteran4 = function() {" fullword ascii
    $s10 = "String.prototype.veteran2 = function () {" fullword ascii
    $s11 = "var opponent = implicit.pop().split(\"" fullword ascii
    $s12 = "var implicit = [validity, traveller,enlightenment,  \"\"+\".\"+(\"britain\",\"holders\",\"distraught\",\"stack\",\"inhale\",\"re" ascii
    $s13 = "var traveller =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".veteran4();" fullword ascii
    $s14 = "var excise = 6/6;" fullword ascii
    $s15 = "jungle = \"_F2_\";" fullword ascii
    $s16 = "var blanched = new buttocks(opponent[0]);" fullword ascii
    $s17 = "congestion(\"aHR0cDovLw==\".veteran4()+\"\\u0073\\u0074\\u0072\\u0073\\u0074\\u0075\\u0064\\u0069\\u006F\\u002E\"+\"\\u0070\\u00" ascii
    $s18 = "  bight = [];" fullword ascii
    $s19 = "var validity = \"QWN0aXZlWE9iamVjdA==\".veteran4();" fullword ascii
    $s20 = "var buttocks = this[implicit.shift()];" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}