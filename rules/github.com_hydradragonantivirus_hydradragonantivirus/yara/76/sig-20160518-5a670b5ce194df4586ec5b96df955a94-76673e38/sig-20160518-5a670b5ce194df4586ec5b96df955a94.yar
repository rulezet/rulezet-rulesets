rule sig_20160518_5a670b5ce194df4586ec5b96df955a94 {
  meta:
    description = "datamaliciousorder - file 20160518_5a670b5ce194df4586ec5b96df955a94.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f4425f68887a0d8929dfd25fa4dc149c83b08d80a3624c2cd04a6e55d78ce7e"

  strings:
    $s1  = "var landmark = [generated, proven,pluto,  \"\"+\".\"+(\"analytical\",\"realist\",\"verzeichnis\",\"roadway\",\"frustrate\",\"pub" ascii
    $s2  = "headstrong = headstrong+ landmark.shift();" fullword ascii
    $s3  = "weasel = ((\"pennant\", \"common\", \"flower\", \"colours\", \"EqEprJfV\") + \"PVWfSPieoYc\").hurries2();" fullword ascii
    $s4  = "var flirt=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".hurries4())&&young[\"c3RhdHVz\".hurries4()] +\"\"==\"MjAw\".hurries4()" ascii
    $s5  = "var flirt=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".hurries4())&&young[\"c3RhdHVz\".hurries4()] +\"\"==\"MjAw\".hurries4()" ascii
    $s6  = "for (var i in measurement){nugget = nugget.replace(i, measurement[i]);}" fullword ascii
    $s7  = "nugget = this;" fullword ascii
    $s8  = "hoist[landmark.shift()](headstrong, progress, true);" fullword ascii
    $s9  = "traditionary(\"aHR0cDovLw==\".hurries4()+\"\\u0072\\u006F\\u0074\\u0073\\u0069\\u006E\\u006F\\u006C\\u0069\\u002E\"+\"\\u0072\\u" ascii
    $s10 = "shoot = ((\"amassed\", \"tripod\", \"gloried\", \"loops\", \"pAXxNuhvfp\") + \"SddyMzE\").hurries2();" fullword ascii
    $s11 = "        var headstrong = hypnotism + \"/\" + literacy ;" fullword ascii
    $s12 = "var golly = landmark.pop().split(\">\");" fullword ascii
    $s13 = "String.prototype.hurries2 = function () {" fullword ascii
    $s14 = "String.prototype.hurries4 = function() {" fullword ascii
    $s15 = "        relation[(shoot + \"o\"+(\"witness\",\"dallas\",\"singapore\",\"contrary\",\"whiles\",\"award\",\"illiterate\",\"fired\"" ascii
    $s16 = "String.prototype.hurries = function () {" fullword ascii
    $s17 = "traditionary(\"aHR0cDovLw==\".hurries4()+\"\\u0072\\u006F\\u0074\\u0073\\u0069\\u006E\\u006F\\u006C\\u0069\\u002E\"+\"\\u0072\\u" ascii
    $s18 = "var acquisitions = this[landmark.shift()];" fullword ascii
    $s19 = "var hypnotism = hoist[landmark.shift()](landmark.shift());" fullword ascii
    $s20 = "function traditionary(involving, literacy) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}