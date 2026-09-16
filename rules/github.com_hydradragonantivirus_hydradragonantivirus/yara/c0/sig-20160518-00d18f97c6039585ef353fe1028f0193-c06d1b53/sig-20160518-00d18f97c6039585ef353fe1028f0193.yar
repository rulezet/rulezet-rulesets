rule sig_20160518_00d18f97c6039585ef353fe1028f0193 {
  meta:
    description = "datamaliciousorder - file 20160518_00d18f97c6039585ef353fe1028f0193.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a3e0525a667f6fd57fd6cd21ce2b17788c068ae17afba870bbce3f48b3dbf4a"

  strings:
    $s1  = "var bullet = [kennel, cannibalism,teeth,  \"\"+\".\"+(\"describes\",\"alluring\",\"maiden\",\"leniency\",\"sickening\",\"derives" ascii
    $s2  = "usive\",\"straightforward\",\"cruiser\",\"spears\",\"08\"), tournament)] = 0;" fullword ascii
    $s3  = "        egress[(warbler + \"o\"+(\"plenary\",\"handjob\",\"harlot\",\"continuity\",\"hired\",\"national\",\"columns\",\"arbiter" ascii
    $s4  = "succeed = succeed+ bullet.shift();" fullword ascii
    $s5  = "for (var i in fiasco){turnkey = turnkey.replace(i, fiasco[i]);}" fullword ascii
    $s6  = "turnkey = this;" fullword ascii
    $s7  = "var specify=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".biblical4())&&outsider[\"c3RhdHVz\".biblical4()] +\"\"==\"MjAw\".bib" ascii
    $s8  = "var specify=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".biblical4())&&outsider[\"c3RhdHVz\".biblical4()] +\"\"==\"MjAw\".bib" ascii
    $s9  = "var fiasco = {" fullword ascii
    $s10 = "tournament = ((\"martian\", \"ichabod\", \"pushing\", \"interpretation\", \"shGyJVsTHY\") + \"Lsarjbo\").biblical2();" fullword ascii
    $s11 = "basic(\"aHR0cDovLw==\".biblical4()+\"\\u0066\\u0065\\u0065\\u0064\\u0063\\u006F\\u006E\\u0073\\u0075\\u006D\\u0065\\u0072\\u002E" ascii
    $s12 = "        egress[(\"counseling\",\"photographic\",\"slavegirl\",\"depends\",\"begone\",\"ascension\",\"sweeps\",\"s\")+\"aveT\"+\"" ascii
    $s13 = "deadened[bullet.shift()](succeed, sociable, true);" fullword ascii
    $s14 = "var amazing = this[bullet.shift()];" fullword ascii
    $s15 = "  across = [];" fullword ascii
    $s16 = "var receive = deadened[bullet.shift()](bullet.shift());" fullword ascii
    $s17 = "        egress[(\"counseling\",\"photographic\",\"slavegirl\",\"depends\",\"begone\",\"ascension\",\"sweeps\",\"s\")+\"aveT\"+\"" ascii
    $s18 = "weasel = ((\"tickle\", \"defensible\", \"grandma\", \"trucks\", \"EioSbuKfYvEV\") + \"iDJojGfmz\").biblical2();" fullword ascii
    $s19 = "var sociable = 6/6;" fullword ascii
    $s20 = "        var egress = new amazing(((\"pretension\",\"structural\",\"uplift\",\"scarred\",\"saints\",\"heliotrope\",\"stunt\",\"ea" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}