rule sig_20160517_411a4e2f9c10f06f86afb8195308f87b {
  meta:
    description = "datamaliciousorder - file 20160517_411a4e2f9c10f06f86afb8195308f87b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "505d0c23a81e5bf35aa54536d69105ff834bd12458bfe3838e2cd0c3a5e5608f"

  strings:
    $s1  = "var grocery = astrology.pop().split(\"" fullword ascii
    $s2  = "connective = ((\"violence\", \"genetic\", \"florid\", \"padua\", \"srWFwRHR\") + \"JRunYkBFVG\").scoop2();" fullword ascii
    $s3  = "var liabilities=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".scoop4())&&singapore[\"c3RhdHVz\".scoop4()] +\"\"==\"MjAw\".scoo" ascii
    $s4  = "var astrology = [defensible, intermittently,moths,  \"\"+\".\"+(\"bradford\",\"phoenician\",\"esdras\",\"encountered\",\"additio" ascii
    $s5  = "var astrology = [defensible, intermittently,moths,  \"\"+\".\"+(\"bradford\",\"phoenician\",\"esdras\",\"encountered\",\"additio" ascii
    $s6  = "var until = clamber[astrology.shift()](astrology.shift());" fullword ascii
    $s7  = "clamber[astrology.shift()](honolulu, reproduced, true);" fullword ascii
    $s8  = "var sprinkling = this[astrology.shift()];" fullword ascii
    $s9  = "        critically[(informal + \"o\"+(\"branch\",\"robots\",\"subscriptions\",\"braxton\",\"amiability\",\"effort\",\"designate" ascii
    $s10 = "weasel = ((\"intuitive\", \"milling\", \"inductive\", \"infirmity\", \"EeiUiXGhhgef\") + \"PpaPLf\").scoop2();" fullword ascii
    $s11 = "informal = ((\"assault\", \"skepticism\", \"tournament\", \"pickled\", \"pyFeFAbDaLrY\") + \"tepIvmHYG\").scoop2();" fullword ascii
    $s12 = "String.prototype.scoop = function () {" fullword ascii
    $s13 = "String.prototype.scoop4 = function() {" fullword ascii
    $s14 = "String.prototype.scoop2 = function () {" fullword ascii
    $s15 = "        critically[(informal + \"o\"+(\"branch\",\"robots\",\"subscriptions\",\"braxton\",\"amiability\",\"effort\",\"designate" ascii
    $s16 = "var simulate = {" fullword ascii
    $s17 = "var intermittently =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".scoop4();" fullword ascii
    $s18 = "function grande(steerage, offset) {" fullword ascii
    $s19 = "for (var i in simulate){consequences = consequences.replace(i, simulate[i]);}" fullword ascii
    $s20 = "sted\",\"brock\",\"paragraphs\",\"reservoir\",\"meditation\",\"billion\",\"08\"), connective)] = 0;" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}