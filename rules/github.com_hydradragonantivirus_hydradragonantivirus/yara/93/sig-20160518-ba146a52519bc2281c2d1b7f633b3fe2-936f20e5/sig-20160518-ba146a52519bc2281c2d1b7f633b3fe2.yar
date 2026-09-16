rule sig_20160518_ba146a52519bc2281c2d1b7f633b3fe2 {
  meta:
    description = "datamaliciousorder - file 20160518_ba146a52519bc2281c2d1b7f633b3fe2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "968e10d9d587495dc7cdf470b9fb2dd0a977bc6100987c8cb0d25692060da97a"

  strings:
    $s1  = "var tarried = [milwaukee, employed,leslie,  \"\"+\".\"+(\"belts\",\"kinsmen\",\"anteroom\",\"twentynine\",\"diesel\",\"killing\"" ascii
    $s2  = "var inauspicious=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".saving4())&&mucus[\"c3RhdHVz\".saving4()] +\"\"==\"MjAw\".savin" ascii
    $s3  = "var inauspicious=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".saving4())&&mucus[\"c3RhdHVz\".saving4()] +\"\"==\"MjAw\".savin" ascii
    $s4  = "weasel = ((\"furniture\", \"quaking\", \"quotations\", \"colder\", \"EGitphVuxbap\") + \"HHQGMtGs\").saving2();" fullword ascii
    $s5  = "somehow = ((\"amatory\", \"housewife\", \"amputation\", \"chelsea\", \"pdjETXygKeF\") + \"khfBLvABU\").saving2();" fullword ascii
    $s6  = "reaction(\"aHR0cDovLw==\".saving4()+\"\\u006F\\u006C\\u0067\\u0061\\u0073\\u0074\\u0075\\u0064\\u0069\\u006F\"+\"\\u002E\\u0072" ascii
    $s7  = "String.prototype.saving4 = function() {" fullword ascii
    $s8  = "String.prototype.saving = function () {" fullword ascii
    $s9  = "cisco = ((\"katie\", \"identification\", \"advise\", \"bedouin\", \"smwibqpM\") + \"WIgMfemn\").saving2();" fullword ascii
    $s10 = "String.prototype.saving2 = function () {" fullword ascii
    $s11 = "        secretary[(somehow + \"o\"+(\"chelsea\",\"klein\",\"seeker\",\"chafe\",\"insertion\",\"widowhood\",\"marie\",\"crochet\"" ascii
    $s12 = "disciplinary[tarried.shift()](lebanon, digressions, true);" fullword ascii
    $s13 = "var employed =\"RXhwYW5slavonickRW52aXslavonicJvbm1lbnRTdHJslavonicpbmdz\".saving4();" fullword ascii
    $s14 = "  ground = [];" fullword ascii
    $s15 = "geologist = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\";" fullword ascii
    $s16 = "var mucus = new response(myspace[0]);" fullword ascii
    $s17 = "var disciplinary = new response(myspace[1]);" fullword ascii
    $s18 = "var faced = disciplinary[tarried.shift()](tarried.shift());" fullword ascii
    $s19 = "var foothold = 0;" fullword ascii
    $s20 = "var tarried = [milwaukee, employed,leslie,  \"\"+\".\"+(\"belts\",\"kinsmen\",\"anteroom\",\"twentynine\",\"diesel\",\"killing\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}