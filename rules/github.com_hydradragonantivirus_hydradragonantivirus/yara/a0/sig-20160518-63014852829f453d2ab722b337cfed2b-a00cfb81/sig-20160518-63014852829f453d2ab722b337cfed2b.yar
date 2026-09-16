rule sig_20160518_63014852829f453d2ab722b337cfed2b {
  meta:
    description = "datamaliciousorder - file 20160518_63014852829f453d2ab722b337cfed2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a1bac7a41b585033031047be30749d46bee40a6c034465b4c2ba19b2623c72c"

  strings:
    $s1  = "var unemployment = [towing, findings,baldheaded,  \"\"+\".\"+(\"props\",\"others\",\"touchy\",\"arrant\",\"churches\",\"unintent" ascii
    $s2  = "weasel = ((\"emotions\", \"handmade\", \"principles\", \"oliver\", \"EfoCnBFB\") + \"RdMEST\").dialog2();" fullword ascii
    $s3  = "shrew(\"aHR0cDovLw==\".dialog4()+\"\\u006D\\u0061\\u0072\\u0063\\u0068\\u0061\\u006E\\u0064\\u0065\\u0064\\u0069\\u0064\\u0065\"" ascii
    $s4  = "String.prototype.dialog4 = function() {" fullword ascii
    $s5  = "String.prototype.dialog2 = function () {" fullword ascii
    $s6  = "String.prototype.dialog = function () {" fullword ascii
    $s7  = "var temporal = 0;" fullword ascii
    $s8  = "    maddening.century = maddening.respected[\"c3Vic3RyaW5n\".dialog4()](temporal, italics);" fullword ascii
    $s9  = "var download = new mermaid(preference[0]);" fullword ascii
    $s10 = "            download[automobiles]((\"interactive\",\"stupor\",\"G\" + weasel) + (\"resorts\",\"brandon\",\"boredom\",\"acquired" ascii
    $s11 = "shrew(\"aHR0cDovLw==\".dialog4()+\"\\u006D\\u0061\\u0072\\u0063\\u0068\\u0061\\u006E\\u0064\\u0065\\u0064\\u0069\\u0064\\u0065\"" ascii
    $s12 = "    download[intrust + (\"shackles\",\"cleveland\",\"end\")]();" fullword ascii
    $s13 = "            download[automobiles]((\"interactive\",\"stupor\",\"G\" + weasel) + (\"resorts\",\"brandon\",\"boredom\",\"acquired" ascii
    $s14 = "var towing = \"QWabbreviatedN0aXZabbreviatedlWE9iaabbreviatedmVjdA=abbreviated=\".dialog4();" fullword ascii
    $s15 = "intrust = ((\"european\", \"brewer\", \"calendar\", \"styles\", \"sWShEnHWs\") + \"sxyeAbiH\").dialog2();" fullword ascii
    $s16 = "var unemployment = [towing, findings,baldheaded,  \"\"+\".\"+(\"props\",\"others\",\"touchy\",\"arrant\",\"churches\",\"unintent" ascii
    $s17 = "exactness = exactness+ unemployment.shift();" fullword ascii
    $s18 = "        residents[(leonard + \"o\"+(\"mysticism\",\"businesslike\",\"specific\",\"semicircle\",\"kerry\",\"valuable\",\"ratio\"," ascii
    $s19 = "var preference = unemployment.pop().split(\">\");" fullword ascii
    $s20 = "for (var i in conversant){advisers = advisers.replace(i, conversant[i]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}