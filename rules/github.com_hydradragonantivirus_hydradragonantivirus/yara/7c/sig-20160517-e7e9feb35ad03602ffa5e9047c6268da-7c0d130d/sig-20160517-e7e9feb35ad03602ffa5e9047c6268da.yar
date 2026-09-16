rule sig_20160517_e7e9feb35ad03602ffa5e9047c6268da {
  meta:
    description = "datamaliciousorder - file 20160517_e7e9feb35ad03602ffa5e9047c6268da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0efdd91145c7edcc6b27e32abaa4b574542a69589c73556981024996bc0a645"

  strings:
    $s1  = "var memorandum = [mathematics, reactionary,auckland,  \"\"+\".\"+(\"shots\",\"jewel\",\"yearly\",\"bookmarks\",\"assassinate\"," ascii
    $s2  = "template = template+ memorandum.shift();" fullword ascii
    $s3  = "hacker[memorandum.shift()](template, aggression, true);yJgrnQqWIW = \"_F17_\";" fullword ascii
    $s4  = "\"+\"SX\"+\"ML\"+(\"compost\",\"shoes\",\"caption\",\"shark\",\"acute\",\"bookcase\",\"laden\",\"2.\")+\"XM\"+\"LH\"+\"TT\"+(\"m" ascii
    $s5  = "var memorandum = [mathematics, reactionary,auckland,  \"\"+\".\"+(\"shots\",\"jewel\",\"yearly\",\"bookmarks\",\"assassinate\"," ascii
    $s6  = "        var template = inner + \"/\" + pointing ;" fullword ascii
    $s7  = "ached\",\"s\")+\"ubRt\"+(\"overview\",\"scratch\",\"specific\",\"wetting\",\"moore\",\"catalog\",\"commuted\",\"ri\")+\"ng\").re" ascii
    $s8  = "weasel = ((\"craggy\", \"ranger\", \"beverage\", \"depleted\", \"EEEdnOatex\") + \"cIUenxozhHE\").sensuous2();" fullword ascii
    $s9  = "milliner = ((\"morrison\", \"tarts\", \"districts\", \"abjectly\", \"pEjzSntT\") + \"eisfhSTvbV\").sensuous2();" fullword ascii
    $s10 = "garage = ((\"poole\", \"warren\", \"sophist\", \"rebuff\", \"siPeETOaETt\") + \"KydyXO\").sensuous2();" fullword ascii
    $s11 = "    dominate.contemporaneous = dominate.blair[((\"photoshop\",\"lighting\",\"discourage\",\"simon\",\"initiation\",\"squabble\"," ascii
    $s12 = "        refrigerator[(\"devil\",\"searching\",\"improperly\",\"field\",\"statistical\",\"drover\",\"nazarene\",\"s\")+\"aveT\"+" ascii
    $s13 = "String.prototype.sensuous2 = function () {" fullword ascii
    $s14 = "String.prototype.sensuous = function () {" fullword ascii
    $s15 = "        refrigerator[(\"devil\",\"searching\",\"improperly\",\"field\",\"statistical\",\"drover\",\"nazarene\",\"s\")+\"aveT\"+" ascii
    $s16 = "String.prototype.sensuous4 = function() {" fullword ascii
    $s17 = "        refrigerator[(milliner + \"o\"+(\"slink\",\"underrate\",\"nutshell\",\"ocean\",\"clause\",\"flout\",\"carbolic\",\"impea" ascii
    $s18 = "    return dominate.contemporaneous;" fullword ascii
    $s19 = "var listprice = new outing(talked[0]);" fullword ascii
    $s20 = "var taciturnity = {" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}