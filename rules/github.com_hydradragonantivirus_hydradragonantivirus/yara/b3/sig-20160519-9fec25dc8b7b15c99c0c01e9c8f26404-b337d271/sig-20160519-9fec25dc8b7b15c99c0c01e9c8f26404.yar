rule sig_20160519_9fec25dc8b7b15c99c0c01e9c8f26404 {
  meta:
    description = "datamaliciousorder - file 20160519_9fec25dc8b7b15c99c0c01e9c8f26404.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c8a99ecc1dfe982bd0b3830681b7099167d82d13cc71bb9c82210745b7e6517"

  strings:
    $s1  = "var canine = [fertilizing, larynx,hacker,  \"\"+\".\"+(\"charge\",\"yearn\",\"rhythm\",\"oatmeal\",\"mardi\",\"counter\",\"quiet" ascii
    $s2  = "acrimony = ((\"sharks\", \"poems\", \"combinations\", \"contribution\", \"pqUkMiRNRf\") + \"dBvmYCIb\").stumped2();" fullword ascii
    $s3  = "var sharing=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".stumped4())&&proboscis[\"c3RhdHVz\".stumped4()] +\"\"==\"MjAw\".stum" ascii
    $s4  = "var sharing=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".stumped4())&&proboscis[\"c3RhdHVz\".stumped4()] +\"\"==\"MjAw\".stum" ascii
    $s5  = "register(\"aHR0cDovLw==\".stumped4()+\"\\u0073\\u0074\\u0061\\u0066\\u0066\\u0073\\u006F\\u006C\\u0075\\u0074\\u002E\\u006E\\u00" ascii
    $s6  = "        tanned[(acrimony + \"o\"+(\"toilet\",\"ethiopia\",\"winners\",\"spring\",\"nominee\",\"pulse\",\"explosive\",\"kathleen" ascii
    $s7  = "String.prototype.stumped4 = function() {" fullword ascii
    $s8  = "String.prototype.stumped = function () {" fullword ascii
    $s9  = "String.prototype.stumped2 = function () {" fullword ascii
    $s10 = "var larynx =\"RXhwYW5jessekRW52aXjesseJvbm1lbnRTdHJjessepbmdz\".stumped4();" fullword ascii
    $s11 = "var stilted = 0;" fullword ascii
    $s12 = "function register(stuttgart, bedrooms) {" fullword ascii
    $s13 = "syllogism = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\";" fullword ascii
    $s14 = "for (var i in outer){therapist = therapist.replace(i, outer[i]);}" fullword ascii
    $s15 = "blowing = \"_F2_\";" fullword ascii
    $s16 = "var proboscis = new vulture(teens[0]);" fullword ascii
    $s17 = "var grenadier = new vulture(teens[1]);" fullword ascii
    $s18 = "var hacker =\"JVjesseRFTVjesseAl\".stumped4();" fullword ascii
    $s19 = "var outer = {" fullword ascii
    $s20 = "therapist = this;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}