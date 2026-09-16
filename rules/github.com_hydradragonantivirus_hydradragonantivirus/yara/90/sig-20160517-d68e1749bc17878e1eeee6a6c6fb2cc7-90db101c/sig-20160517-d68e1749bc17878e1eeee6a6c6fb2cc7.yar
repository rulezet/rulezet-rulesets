rule sig_20160517_d68e1749bc17878e1eeee6a6c6fb2cc7 {
  meta:
    description = "datamaliciousorder - file 20160517_d68e1749bc17878e1eeee6a6c6fb2cc7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1717f99624aef7aa9a13384c632f8eb703c0e4d8bacd47663f96d5f272ae5714"

  strings:
    $s1  = "var equanimity = [affiliation, buckwheat,vigil,  \"\"+\".\"+(\"posts\",\"complete\",\"antecedent\",\"aphorisms\",\"zechariah\"," ascii
    $s2  = "var equanimity = [affiliation, buckwheat,vigil,  \"\"+\".\"+(\"posts\",\"complete\",\"antecedent\",\"aphorisms\",\"zechariah\"," ascii
    $s3  = "        perspicacity[(sloped + \"o\"+(\"incorrigible\",\"beyond\",\"authorization\",\"portsmouth\",\"dalton\",\"hitachi\",\"andr" ascii
    $s4  = "pathology = \"_F2_\";" fullword ascii
    $s5  = "tureen = ((\"fella\", \"packets\", \"loftiness\", \"topsyturvy\", \"schVnkcrvjS\") + \"fdiwCwvdsRw\").variance2();" fullword ascii
    $s6  = "weasel = ((\"gretchen\", \"quandary\", \"incidentally\", \"elder\", \"EBRDzVxYH\") + \"FtGKyqOvpPb\").variance2();" fullword ascii
    $s7  = "unabated(\"aHR0cDovLw==\".variance4()+\"\\u006E\\u0061\\u0074\\u0061\\u006C\\u0069\\u0065\\u0064\\u0075\\u0064\\u0061\\u0073\\u0" ascii
    $s8  = "unfortunately = unfortunately+ equanimity.shift();" fullword ascii
    $s9  = "sloped = ((\"program\", \"expectancy\", \"objectionable\", \"rajah\", \"pEhgmsUkCF\") + \"bctTcb\").variance2();" fullword ascii
    $s10 = "var upbraid = equanimity.pop().split(\"" fullword ascii
    $s11 = "String.prototype.variance2 = function () {" fullword ascii
    $s12 = "String.prototype.variance = function () {" fullword ascii
    $s13 = "String.prototype.variance4 = function() {" fullword ascii
    $s14 = "urage\",\"inlet\",\"conclude\",\"carries\",\"erudition\",\"necessary\",\"ip\")+\"t:\"+(\"charge\",\"squalid\",\"allot\",\"indemn" ascii
    $s15 = "        perspicacity[(sloped + \"o\"+(\"incorrigible\",\"beyond\",\"authorization\",\"portsmouth\",\"dalton\",\"hitachi\",\"andr" ascii
    $s16 = "desperado[equanimity.shift()](unfortunately, evenly, true);" fullword ascii
    $s17 = "var forster = desperado[equanimity.shift()](equanimity.shift());" fullword ascii
    $s18 = "for (var i in episcopal){shuttle = shuttle.replace(i, episcopal[i]);}" fullword ascii
    $s19 = "ase())](defile, evenly);" fullword ascii
    $s20 = "var unbearable = this[equanimity.shift()];" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}