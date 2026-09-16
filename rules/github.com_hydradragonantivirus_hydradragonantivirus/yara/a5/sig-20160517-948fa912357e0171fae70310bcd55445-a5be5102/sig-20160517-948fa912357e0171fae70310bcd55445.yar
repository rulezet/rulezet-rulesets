rule sig_20160517_948fa912357e0171fae70310bcd55445 {
  meta:
    description = "datamaliciousorder - file 20160517_948fa912357e0171fae70310bcd55445.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bca1fc24e380fb2301c0230168f3805f9d246757416cb9b858dfcfe0fcc7008"

  strings:
    $s1  = "var quantum = [users, cacique,vicarage,  \"\"+\".\"+(\"parry\",\"addressing\",\"humbug\",\"ended\",\"computational\",\"andes\"," ascii
    $s2  = "var quantum = [users, cacique,vicarage,  \"\"+\".\"+(\"parry\",\"addressing\",\"humbug\",\"ended\",\"computational\",\"andes\"," ascii
    $s3  = "clipping = clipping+ quantum.shift();" fullword ascii
    $s4  = "function wales(granted, fares) {" fullword ascii
    $s5  = "            introduces[hustle]((\"somber\",\"wafer\",\"G\" + weasel) + (\"indoor\",\"metals\",\"demonstrated\",\"raising\",\"T\"" ascii
    $s6  = "            introduces[hustle]((\"somber\",\"wafer\",\"G\" + weasel) + (\"indoor\",\"metals\",\"demonstrated\",\"raising\",\"T\"" ascii
    $s7  = "weasel = ((\"ignoramus\", \"overcrowded\", \"rolled\", \"edition\", \"EjoSmgwMHoJ\") + \"WcmQAyc\").fitting2();" fullword ascii
    $s8  = "unripe = ((\"apulia\", \"serial\", \"provision\", \"syndrome\", \"swjmEKO\") + \"goGoLbnTWwe\").fitting2();" fullword ascii
    $s9  = "var inductive = quantum.pop().split(\"" fullword ascii
    $s10 = "ly\",\"passer\",\"infrastructure\",\"bergen\",\"08\"), unripe)] = 0;" fullword ascii
    $s11 = "String.prototype.fitting2 = function () {" fullword ascii
    $s12 = "String.prototype.fitting = function () {" fullword ascii
    $s13 = "String.prototype.fitting4 = function() {" fullword ascii
    $s14 = "        var clipping = therapeutic + \"/\" + fares ;" fullword ascii
    $s15 = "pottery[quantum.shift()](clipping, midwinter, true);" fullword ascii
    $s16 = ",\"branch\",\"apnic\",\"essayist\",\"depreciation\",\"tributary\",\"arizona\",\"8i\")+\"tion\").replace(\"0\"+(\"level\",\"homes" ascii
    $s17 = "orthodoxy = this;" fullword ascii
    $s18 = "var extending = 0;" fullword ascii
    $s19 = "hustle = \"b3Blbg==\".fitting4();;" fullword ascii
    $s20 = "var clammy = {" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}