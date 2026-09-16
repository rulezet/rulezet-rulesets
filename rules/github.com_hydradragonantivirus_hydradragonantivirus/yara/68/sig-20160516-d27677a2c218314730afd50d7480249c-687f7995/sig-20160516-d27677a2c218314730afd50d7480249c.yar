rule sig_20160516_d27677a2c218314730afd50d7480249c {
  meta:
    description = "datamaliciousorder - file 20160516_d27677a2c218314730afd50d7480249c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e353ad35903c1169d588c485614a2ef8c8cba62a5a0b1505462aeb45ae51b75c"

  strings:
    $s1  = "        choler[(papal + \"o\"+(\"posthumous\",\"derby\",\"minneapolis\",\"incomplete\",\"ripped\",\"reports\",\"fawning\",\"eleg" ascii
    $s2  = "        choler[(papal + \"o\"+(\"posthumous\",\"derby\",\"minneapolis\",\"incomplete\",\"ripped\",\"reports\",\"fawning\",\"eleg" ascii
    $s3  = "ldest\",\"whosoever\",\"royalist\",\"among\",\"deserve\",\"ip\")+\"t:\"+(\"remind\",\"openness\",\"diving\",\"birmingham\",\"dia" ascii
    $s4  = "weasel = ((\"squeamish\", \"novelty\", \"attorneys\", \"miserly\", \"ETBXEsSU\") + \"RqgfQf\").extradition2();" fullword ascii
    $s5  = "papal = ((\"documentation\", \"changing\", \"arrange\", \"prescribe\", \"pHSoFyyCL\") + \"emajvvbh\").extradition2();" fullword ascii
    $s6  = "taper = ((\"vegas\", \"reprints\", \"uganda\", \"stylish\", \"sdNzgTJm\") + \"CCSgWhiel\").extradition2();" fullword ascii
    $s7  = "var alluring = oblivious.pop().split(\"" fullword ascii
    $s8  = "String.prototype.extradition4 = function() {" fullword ascii
    $s9  = "String.prototype.extradition = function () {" fullword ascii
    $s10 = "String.prototype.extradition2 = function () {" fullword ascii
    $s11 = "var eucalyptus=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".extradition4())&&graven[\"c3RhdHVz\".extradition4()] +\"\"==\"MjA" ascii
    $s12 = "var eucalyptus=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".extradition4())&&graven[\"c3RhdHVz\".extradition4()] +\"\"==\"MjA" ascii
    $s13 = "for (var i in cricket){ballet = ballet.replace(i, cricket[i]);}" fullword ascii
    $s14 = "function inkjet(periods, roger) {" fullword ascii
    $s15 = "ballet = this;" fullword ascii
    $s16 = "var graven = new anybody(alluring[0]);" fullword ascii
    $s17 = "var garland = 6/6;" fullword ascii
    $s18 = "var oblivious = [collecting, overseas,multifarious,  \"\"+\".\"+(\"paired\",\"harlot\",\"retired\",\"palliate\",\"booth\",\"soon" ascii
    $s19 = "var cricket = {" fullword ascii
    $s20 = "var multifarious =\"JVRFTVAl\".extradition4();" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}