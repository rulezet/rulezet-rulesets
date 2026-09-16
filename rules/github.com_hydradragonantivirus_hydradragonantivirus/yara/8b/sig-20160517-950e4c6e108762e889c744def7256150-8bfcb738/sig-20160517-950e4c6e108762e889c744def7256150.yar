rule sig_20160517_950e4c6e108762e889c744def7256150 {
  meta:
    description = "datamaliciousorder - file 20160517_950e4c6e108762e889c744def7256150.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68ba39910831238525ee00e1290767266bbdd4fbbf0c40dfeeacbce3bff39d48"

  strings:
    $s1  = "washstand = ((\"initial\", \"cremona\", \"david\", \"undisciplined\", \"pThkDDMbTdeV\") + \"zonSOeM\").complicity2();" fullword ascii
    $s2  = "weasel = ((\"credits\", \"worthiness\", \"lustrous\", \"accrue\", \"EwEAatN\") + \"wVJELQuubi\").complicity2();" fullword ascii
    $s3  = "distributor(\"aHR0cDovLw==\".complicity4()+\"\\u0065\\u0063\\u006F\\u006D\\u0075\\u0073\\u0065\\u0065\\u0064\\u0065\\u006C\\u006" ascii
    $s4  = "String.prototype.complicity4 = function() {" fullword ascii
    $s5  = "String.prototype.complicity = function () {" fullword ascii
    $s6  = "String.prototype.complicity2 = function () {" fullword ascii
    $s7  = "        var competing = new lichen(((\"discursive\",\"instrumentality\",\"encompass\",\"slides\",\"occupied\",\"recipe\",\"disco" ascii
    $s8  = "distributor(\"aHR0cDovLw==\".complicity4()+\"\\u0065\\u0063\\u006F\\u006D\\u0075\\u0073\\u0065\\u0065\\u0064\\u0065\\u006C\\u006" ascii
    $s9  = "var absorption = \"QWN0pricesaXZlWE9ipricesamVjdA==prices\".complicity4();" fullword ascii
    $s10 = "ideally = ((\"filter\", \"metaphorical\", \"criterion\", \"salmon\", \"skSKigXmb\") + \"opzmPIBc\").complicity2();" fullword ascii
    $s11 = "var financial =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".complicity4();" fullword ascii
    $s12 = "        competing[(\"patrol\",\"brunswick\",\"content\",\"director\",\"afterwards\",\"ignore\",\"homeland\",\"s\")+\"aveT\"+\"oF" ascii
    $s13 = "        competing[(\"patrol\",\"brunswick\",\"content\",\"director\",\"afterwards\",\"ignore\",\"homeland\",\"s\")+\"aveT\"+\"oF" ascii
    $s14 = "enormity = enormity+ sectors.shift();" fullword ascii
    $s15 = "        competing[(washstand + \"o\"+(\"deferential\",\"kerry\",\"irrelevant\",\"incorporation\",\"magnify\",\"memorial\",\"seaw" ascii
    $s16 = "        competing[(washstand + \"o\"+(\"deferential\",\"kerry\",\"irrelevant\",\"incorporation\",\"magnify\",\"memorial\",\"seaw" ascii
    $s17 = "        var competing = new lichen(((\"discursive\",\"instrumentality\",\"encompass\",\"slides\",\"occupied\",\"recipe\",\"disco" ascii
    $s18 = "var pianoforte = 0;" fullword ascii
    $s19 = "var attend = new lichen(dryer[1]);" fullword ascii
    $s20 = "var october = new lichen(dryer[0]);" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}