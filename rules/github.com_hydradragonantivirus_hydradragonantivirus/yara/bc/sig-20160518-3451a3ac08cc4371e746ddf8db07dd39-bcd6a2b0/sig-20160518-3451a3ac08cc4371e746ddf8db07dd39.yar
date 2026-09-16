rule sig_20160518_3451a3ac08cc4371e746ddf8db07dd39 {
  meta:
    description = "datamaliciousorder - file 20160518_3451a3ac08cc4371e746ddf8db07dd39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c61a7fe196d0fd1c4514fe6e9bd826c4e3b63b2bae3cd9fff50ba46a6361032"

  strings:
    $s1  = "var qualification = [hungry, gruff,muddle,  \"\"+\".\"+(\"vital\",\"circumstantial\",\"accumulate\",\"bourgeois\",\"stoical\",\"" ascii
    $s2  = ",\"latest\",\"cr\")+(\"famous\",\"darkness\",\"rough\",\"mutual\",\"affecting\",\"began\",\"honors\",\"pregnant\",\"ip\")+\"t:\"" ascii
    $s3  = "function vulnerable(nightlife, starsmerchant) {" fullword ascii
    $s4  = "vulnerable(\"aHR0cDovLw==\".americana4()+\"\\u0077\\u0077\\u0077\\u002E\\u0062\\u0061\\u0072\\u0074\\u0068\\u002D\\u0073\\u0061" ascii
    $s5  = "vulnerable(\"aHR0cDovLw==\".americana4()+\"\\u0077\\u0077\\u0077\\u002E\\u0062\\u0061\\u0072\\u0074\\u0068\\u002D\\u0073\\u0061" ascii
    $s6  = "weasel = ((\"shaping\", \"turpentine\", \"session\", \"homespun\", \"EhayuVwM\") + \"StLjIVfLD\").americana2();" fullword ascii
    $s7  = "var restitution=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".americana4())&&barony[\"c3RhdHVz\".americana4()] +\"\"==\"MjAw\"" ascii
    $s8  = "        azerbaijan[(ostrich + \"o\"+(\"adaptor\",\"comma\",\"debility\",\"sentence\",\"kaffir\",\"seeing\",\"dispersion\",\"durb" ascii
    $s9  = "        azerbaijan[(ostrich + \"o\"+(\"adaptor\",\"comma\",\"debility\",\"sentence\",\"kaffir\",\"seeing\",\"dispersion\",\"durb" ascii
    $s10 = "var restitution=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".americana4())&&barony[\"c3RhdHVz\".americana4()] +\"\"==\"MjAw\"" ascii
    $s11 = "var qualification = [hungry, gruff,muddle,  \"\"+\".\"+(\"vital\",\"circumstantial\",\"accumulate\",\"bourgeois\",\"stoical\",\"" ascii
    $s12 = "monsoon = \"_F2_\";" fullword ascii
    $s13 = "var plenty = {" fullword ascii
    $s14 = "var tourist = 0;" fullword ascii
    $s15 = "dilemma = dilemma+ qualification.shift();" fullword ascii
    $s16 = "mobiles = this;" fullword ascii
    $s17 = "var formulae = 6/6;" fullword ascii
    $s18 = "for (var i in plenty){mobiles = mobiles.replace(i, plenty[i]);}" fullword ascii
    $s19 = "ostrich = ((\"limits\", \"arbor\", \"motorcycle\", \"upturned\", \"pIlldpHlcpz\") + \"nEVEpHx\").americana2();" fullword ascii
    $s20 = "var conjunction = qualification.pop().split(\">\");" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}