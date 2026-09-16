rule sig_20160519_d7728edf5385dd9f2226f8262ec61e21 {
  meta:
    description = "datamaliciousorder - file 20160519_d7728edf5385dd9f2226f8262ec61e21.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50ecb9ed41e3f3627bd2e0a4af855490b0bedf423156d56ba89f2869b2902a18"

  strings:
    $s1  = "var casuistry = [debris, royal,deceiver,  \"\"+\".\"+(\"executor\",\"domineering\",\"minus\",\"alloy\",\"forecastle\",\"peddler" ascii
    $s2  = "var coined=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".badge4())&&lettuce[\"c3RhdHVz\".badge4()] +\"\"==\"MjAw\".badge4()&&t" ascii
    $s3  = "var coined=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".badge4())&&lettuce[\"c3RhdHVz\".badge4()] +\"\"==\"MjAw\".badge4()&&t" ascii
    $s4  = "    if ( bloggers[ i ] === undefined )" fullword ascii
    $s5  = "weasel = ((\"contacted\", \"choir\", \"atkins\", \"uplifting\", \"EepUEsLcYAHc\") + \"RemYBtsaX\").badge2();" fullword ascii
    $s6  = "var casuistry = [debris, royal,deceiver,  \"\"+\".\"+(\"executor\",\"domineering\",\"minus\",\"alloy\",\"forecastle\",\"peddler" ascii
    $s7  = "falcon(\"aHR0cDovLw==\".badge4()+\"\\u006D\\u0061\\u0072\\u0063\\u0068\\u0061\\u006E\\u0064\\u0065\\u0064\\u0069\\u0064\\u0065\"" ascii
    $s8  = "story = ((\"tassel\", \"dozen\", \"syracuse\", \"tardy\", \"sKNmmYHaJ\") + \"LBIgjByN\").badge2();" fullword ascii
    $s9  = "var upcoming = 6/6;" fullword ascii
    $s10 = "String.prototype.badge = function () {" fullword ascii
    $s11 = "String.prototype.badge4 = function() {" fullword ascii
    $s12 = "String.prototype.badge2 = function () {" fullword ascii
    $s13 = "var inches = new domain(bison[1]);" fullword ascii
    $s14 = "cursor = this;" fullword ascii
    $s15 = "lexible\",\"strap\",\"please\",\"08\"), story)] = 0;" fullword ascii
    $s16 = "var debris = \"QWallowN0aXZallowlWE9iaallowmVjdA=allow=\".badge4();" fullword ascii
    $s17 = "        stucco[(londoner + \"o\"+(\"bouncing\",\"moiety\",\"exemplar\",\"existed\",\"bombastic\",\"impartially\",\"brands\",\"do" ascii
    $s18 = "function falcon(parsley, congo) {" fullword ascii
    $s19 = "var obviously = 0;" fullword ascii
    $s20 = "var royal =\"RXhwYW5allowkRW52aXallowJvbm1lbnRTdHJallowpbmdz\".badge4();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}