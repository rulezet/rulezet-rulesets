rule sig_20160517_cbeff62095fda514394b5f0b745f030b {
  meta:
    description = "datamaliciousorder - file 20160517_cbeff62095fda514394b5f0b745f030b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6119cebd5131f383f8172603f5b9cf49eb8fa0a76e0fc609fcf417851e7cfa68"

  strings:
    $s1  = "var reputable = [chronology, vacuum,interpose,  \"\"+\".\"+(\"indemnity\",\"depression\",\"unremitting\",\"followed\",\"harem\"," ascii
    $s2  = "var inherited=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".aspects4())&&airing[\"c3RhdHVz\".aspects4()] +\"\"==\"MjAw\".aspec" ascii
    $s3  = "var inherited=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".aspects4())&&airing[\"c3RhdHVz\".aspects4()] +\"\"==\"MjAw\".aspec" ascii
    $s4  = "var chronology = \"QWimposedN0aXZimposedlWE9iaimposedmVjdA=imposed=\".aspects4();" fullword ascii
    $s5  = "var reputable = [chronology, vacuum,interpose,  \"\"+\".\"+(\"indemnity\",\"depression\",\"unremitting\",\"followed\",\"harem\"," ascii
    $s6  = "nurture = nurture+ reputable.shift();" fullword ascii
    $s7  = "minor = ((\"fevered\", \"moldova\", \"sable\", \"typhoid\", \"sMMksLD\") + \"voMVbntRGes\").aspects2();" fullword ascii
    $s8  = "weasel = ((\"thumbnail\", \"borough\", \"quarto\", \"mustang\", \"EQqXlja\") + \"qfJOqEnmzF\").aspects2();" fullword ascii
    $s9  = "var blissful = reputable.pop().split(\"" fullword ascii
    $s10 = "String.prototype.aspects = function () {" fullword ascii
    $s11 = "function systems(kinsmen, hyperbole) {" fullword ascii
    $s12 = "String.prototype.aspects4 = function() {" fullword ascii
    $s13 = "String.prototype.aspects2 = function () {" fullword ascii
    $s14 = "var tucker = {" fullword ascii
    $s15 = "for (var i in tucker){steeple = steeple.replace(i, tucker[i]);}" fullword ascii
    $s16 = "var dampness = this[reputable.shift()];" fullword ascii
    $s17 = "var vacuum =\"RXhwYW5imposedkRW52aXimposedJvbm1lbnRTdHJimposedpbmdz\".aspects4();" fullword ascii
    $s18 = "hant, sister);" fullword ascii
    $s19 = "steeple = this;" fullword ascii
    $s20 = "var interpose =\"JVimposedRFTVimposedAl\".aspects4();" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}