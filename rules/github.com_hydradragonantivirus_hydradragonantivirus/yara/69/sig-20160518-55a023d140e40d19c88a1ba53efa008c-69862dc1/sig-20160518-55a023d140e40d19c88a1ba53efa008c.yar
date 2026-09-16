rule sig_20160518_55a023d140e40d19c88a1ba53efa008c {
  meta:
    description = "datamaliciousorder - file 20160518_55a023d140e40d19c88a1ba53efa008c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26f26a3a7d33a99ae54eedf83119728f2afec311145077e0c8ecf0ca41a69768"

  strings:
    $s1  = "var packard = [naturals, survivor,pillage,  \"\"+\".\"+(\"chain\",\"thistle\",\"advantage\",\"peoples\",\"transform\",\"showers" ascii
    $s2  = "obtuse = ((\"tagalog\", \"syntax\", \"floppy\", \"coaching\", \"ppyhjDFkC\") + \"hPlcGmfvukA\").vital2();" fullword ascii
    $s3  = "archangel = ((\"broth\", \"oblivious\", \"combo\", \"backgrounds\", \"sLDNLCvw\") + \"hgIDOvWuJCm\").vital2();" fullword ascii
    $s4  = "var versed=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".vital4())&&soviet[\"c3RhdHVz\".vital4()] +\"\"==\"MjAw\".vital4()&&ty" ascii
    $s5  = "var versed=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".vital4())&&soviet[\"c3RhdHVz\".vital4()] +\"\"==\"MjAw\".vital4()&&ty" ascii
    $s6  = "        var coffer = new dispatch(((\"bavarian\",\"agnostic\",\"formosa\",\"swooping\",\"passport\",\"phosphoric\",\"partiality" ascii
    $s7  = "backbone = backbone+ packard.shift();" fullword ascii
    $s8  = "buckle(\"aHR0cDovLw==\".vital4()+\"\\u0069\\u006B\\u0073\\u0074\\u0075\\u0064\\u0069\\u006F\\u002E\\u0077\\u007A\"+\"\\u002E\\u0" ascii
    $s9  = "String.prototype.vital2 = function () {" fullword ascii
    $s10 = "String.prototype.vital = function () {" fullword ascii
    $s11 = "var pencil = packard.pop().split(\">\");" fullword ascii
    $s12 = "weasel = ((\"perspective\", \"perth\", \"sycamore\", \"drivers\", \"ExajMKQbg\") + \"mlpJLQXiE\").vital2();" fullword ascii
    $s13 = "String.prototype.vital4 = function() {" fullword ascii
    $s14 = "        var coffer = new dispatch(((\"bavarian\",\"agnostic\",\"formosa\",\"swooping\",\"passport\",\"phosphoric\",\"partiality" ascii
    $s15 = "mouthpiece = this;" fullword ascii
    $s16 = "topsail[packard.shift()](backbone, younger, true);" fullword ascii
    $s17 = "var soviet = new dispatch(pencil[0]);" fullword ascii
    $s18 = "buckle(\"aHR0cDovLw==\".vital4()+\"\\u0069\\u006B\\u0073\\u0074\\u0075\\u0064\\u0069\\u006F\\u002E\\u0077\\u007A\"+\"\\u002E\\u0" ascii
    $s19 = "var younger = 6/6;" fullword ascii
    $s20 = "var transgress = topsail[packard.shift()](packard.shift());" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}