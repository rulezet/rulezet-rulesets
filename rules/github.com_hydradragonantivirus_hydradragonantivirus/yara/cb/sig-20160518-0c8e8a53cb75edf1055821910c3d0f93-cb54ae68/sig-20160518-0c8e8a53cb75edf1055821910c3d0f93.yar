rule sig_20160518_0c8e8a53cb75edf1055821910c3d0f93 {
  meta:
    description = "datamaliciousorder - file 20160518_0c8e8a53cb75edf1055821910c3d0f93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46672d7cf970fd4f5038beef5c0d7b54a60f82f33a204fe4cada10c47dec7243"

  strings:
    $s1  = "var sized=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".believed4())&&fretted[\"c3RhdHVz\".believed4()] +\"\"==\"MjAw\".believ" ascii
    $s2  = "var sized=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".believed4())&&fretted[\"c3RhdHVz\".believed4()] +\"\"==\"MjAw\".believ" ascii
    $s3  = "acidity = acidity+ hurrah.shift();" fullword ascii
    $s4  = "weasel = ((\"loathing\", \"synonym\", \"negotiations\", \"mandate\", \"EQMPOciIIM\") + \"NaWiEWprc\").believed2();" fullword ascii
    $s5  = "orchid(\"aHR0cDovLw==\".believed4()+\"\\u0074\\u0068\\u0065\\u006D\\u0061\\u0074\\u0068\\u0077\\u0065\\u0062\\u0073\\u0069\\u007" ascii
    $s6  = "String.prototype.believed2 = function () {" fullword ascii
    $s7  = "String.prototype.believed = function () {" fullword ascii
    $s8  = "        oblation[(interviews + \"o\"+(\"iridescent\",\"haven\",\"paired\",\"climbing\",\"divorce\",\"wainscot\",\"appendix\",\"p" ascii
    $s9  = "String.prototype.believed4 = function() {" fullword ascii
    $s10 = "        oblation[(interviews + \"o\"+(\"iridescent\",\"haven\",\"paired\",\"climbing\",\"divorce\",\"wainscot\",\"appendix\",\"p" ascii
    $s11 = "var hurrah = [magyar, jokes,holders,  \"\"+\".\"+(\"ascension\",\"thrush\",\"container\",\"mishap\",\"unremitting\",\"securely\"" ascii
    $s12 = "var cosmic = this[hurrah.shift()];" fullword ascii
    $s13 = "elizabeth[hurrah.shift()](acidity, municipality, true);" fullword ascii
    $s14 = "var municipality = 6/6;" fullword ascii
    $s15 = "  disquisition = [];" fullword ascii
    $s16 = "function orchid(glance, kennel) {" fullword ascii
    $s17 = "for (var i in parallel){deviate = deviate.replace(i, parallel[i]);}" fullword ascii
    $s18 = "var elizabeth = new cosmic(talmud[1]);" fullword ascii
    $s19 = "deviate = this;" fullword ascii
    $s20 = "var fretted = new cosmic(talmud[0]);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}