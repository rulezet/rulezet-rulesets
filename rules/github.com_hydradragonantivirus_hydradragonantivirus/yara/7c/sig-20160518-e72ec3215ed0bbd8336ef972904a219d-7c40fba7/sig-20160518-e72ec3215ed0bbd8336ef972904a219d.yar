rule sig_20160518_e72ec3215ed0bbd8336ef972904a219d {
  meta:
    description = "datamaliciousorder - file 20160518_e72ec3215ed0bbd8336ef972904a219d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "051dca5dad47b8d44ea60068b775b7fabea85509fe12a5bcc11ff1f7cd9cf4ed"

  strings:
    $s1  = "var became = [analogies, forelock,consecutive,  \"\"+\".\"+(\"houston\",\"highland\",\"administrators\",\"impiety\",\"reciprocal" ascii
    $s2  = "var revelation=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".crony4())&&dating[\"c3RhdHVz\".crony4()] +\"\"==\"MjAw\".crony4()" ascii
    $s3  = "var revelation=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".crony4())&&dating[\"c3RhdHVz\".crony4()] +\"\"==\"MjAw\".crony4()" ascii
    $s4  = "        violin[(saddened + \"o\"+(\"relentlessly\",\"lucia\",\"disbelief\",\"purplish\",\"venomous\",\"composed\",\"fatty\",\"co" ascii
    $s5  = "function stalking(seraglio, maidenhead) {" fullword ascii
    $s6  = "        var adventuress = potion + \"/\" + maidenhead ;" fullword ascii
    $s7  = "weasel = ((\"sedimentary\", \"above\", \"otter\", \"frenchwoman\", \"EToOitr\") + \"RlxVqJh\").crony2();" fullword ascii
    $s8  = "stalking(\"aHR0cDovLw==\".crony4()+\"\\u0062\\u006F\\u0064\\u006C\\u0061\\u006B\\u002E\\u0065\\u0075\\u0077\\u0065\"+\"\\u0062" ascii
    $s9  = "String.prototype.crony2 = function () {" fullword ascii
    $s10 = "var upcoming = {" fullword ascii
    $s11 = "String.prototype.crony = function () {" fullword ascii
    $s12 = "terate\",\"journalism\",\"desperado\",\"authentic\",\"immunity\",\"08\"), homesickness)] = 0;" fullword ascii
    $s13 = "String.prototype.crony4 = function() {" fullword ascii
    $s14 = "for (var i in upcoming){outdo = outdo.replace(i, upcoming[i]);}" fullword ascii
    $s15 = "        violin[(saddened + \"o\"+(\"relentlessly\",\"lucia\",\"disbelief\",\"purplish\",\"venomous\",\"composed\",\"fatty\",\"co" ascii
    $s16 = "var became = [analogies, forelock,consecutive,  \"\"+\".\"+(\"houston\",\"highland\",\"administrators\",\"impiety\",\"reciprocal" ascii
    $s17 = "adventuress = adventuress+ became.shift();" fullword ascii
    $s18 = "homesickness = ((\"quietest\", \"boredom\", \"scarecrow\", \"mammy\", \"snoiqojDaisW\") + \"lmjPFzutYc\").crony2();" fullword ascii
    $s19 = "meant = \"b3Blbg==\".crony4();;" fullword ascii
    $s20 = "var glorify = 0;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}