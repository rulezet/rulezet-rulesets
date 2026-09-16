rule sig_20160517_ff88afe78d0642945a54e3234cb705e2 {
  meta:
    description = "datamaliciousorder - file 20160517_ff88afe78d0642945a54e3234cb705e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "889e9cce967adcd39d85e19a9561c165a2b76082f391951f839eb0ba1e72513d"

  strings:
    $s1  = "var pests = [insides, effie,nominee,  \"\"+\".\"+(\"trauma\",\"versus\",\"absolved\",\"coins\",\"person\",\"presentday\",\"funct" ascii
    $s2  = "command = \"_F2_\";" fullword ascii
    $s3  = "var abetted=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".parrot4())&&clarity[\"c3RhdHVz\".parrot4()] +\"\"==\"MjAw\".parrot4(" ascii
    $s4  = "var pests = [insides, effie,nominee,  \"\"+\".\"+(\"trauma\",\"versus\",\"absolved\",\"coins\",\"person\",\"presentday\",\"funct" ascii
    $s5  = "var abetted=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".parrot4())&&clarity[\"c3RhdHVz\".parrot4()] +\"\"==\"MjAw\".parrot4(" ascii
    $s6  = ",\"bounteous\",\"meters\",\"headstrong\",\"08\"), decided)] = 0;" fullword ascii
    $s7  = "lusty(\"aHR0cDovLw==\".parrot4()+\"\\u0068\\u0065\\u0061\\u0076\\u0065\\u006E\\u0062\\u006F\\u0075\\u006E\\u0064\\u006D\\u0069" ascii
    $s8  = "locust = ((\"develop\", \"federation\", \"refrigerator\", \"bicycle\", \"pOrDQhuuA\") + \"dQXqSBFXvbz\").parrot2();" fullword ascii
    $s9  = "decided = ((\"propound\", \"wellfounded\", \"extended\", \"diversity\", \"sHdmmgocl\") + \"mReoBPLNtz\").parrot2();" fullword ascii
    $s10 = "weasel = ((\"informer\", \"professionals\", \"helping\", \"editors\", \"EagsogQXSb\") + \"LSkcBbH\").parrot2();" fullword ascii
    $s11 = "        nightcap[(locust + \"o\"+(\"peremptory\",\"vista\",\"issues\",\"sceptic\",\"pyrites\",\"ailing\",\"katie\",\"festive\"," ascii
    $s12 = "String.prototype.parrot = function () {" fullword ascii
    $s13 = "String.prototype.parrot4 = function() {" fullword ascii
    $s14 = "String.prototype.parrot2 = function () {" fullword ascii
    $s15 = "var gardening = pests.pop().split(\"" fullword ascii
    $s16 = "            clarity[identified]((\"glance\",\"ditto\",\"G\" + weasel) + (\"children\",\"magpie\",\"chamber\",\"locally\",\"T\")," ascii
    $s17 = "            clarity[identified]((\"glance\",\"ditto\",\"G\" + weasel) + (\"children\",\"magpie\",\"chamber\",\"locally\",\"T\")," ascii
    $s18 = "var bowling = 0;" fullword ascii
    $s19 = "se())](bowling, parasitic);" fullword ascii
    $s20 = "var clarity = new individually(gardening[0]);" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}