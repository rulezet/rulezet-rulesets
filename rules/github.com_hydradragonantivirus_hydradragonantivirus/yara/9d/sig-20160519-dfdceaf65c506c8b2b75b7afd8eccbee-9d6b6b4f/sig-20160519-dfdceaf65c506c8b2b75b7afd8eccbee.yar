rule sig_20160519_dfdceaf65c506c8b2b75b7afd8eccbee {
  meta:
    description = "datamaliciousorder - file 20160519_dfdceaf65c506c8b2b75b7afd8eccbee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "245e8f72d4e7325bd944392b9a7a88673de7a274585a4d6398c372a1978a07ac"

  strings:
    $s1  = "var script = [robust, insidious,longest,  \"\"+\".\"+(\"afterwards\",\"squeal\",\"tolerant\",\"cosmopolitan\",\"crete\",\"theolo" ascii
    $s2  = "var script = [robust, insidious,longest,  \"\"+\".\"+(\"afterwards\",\"squeal\",\"tolerant\",\"cosmopolitan\",\"crete\",\"theolo" ascii
    $s3  = "shant = shant+ script.shift();" fullword ascii
    $s4  = "var burlesque = script.pop().split(\">\");" fullword ascii
    $s5  = "var nicest = burdensome[script.shift()](script.shift());" fullword ascii
    $s6  = "burdensome[script.shift()](shant, abortive, true);" fullword ascii
    $s7  = "var medicines = this[script.shift()];" fullword ascii
    $s8  = "var organizer=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".wounding4())&&deaden[\"c3RhdHVz\".wounding4()] +\"\"==\"MjAw\".wou" ascii
    $s9  = "var organizer=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".wounding4())&&deaden[\"c3RhdHVz\".wounding4()] +\"\"==\"MjAw\".wou" ascii
    $s10 = "parole = ((\"founded\", \"potentially\", \"upstart\", \"phenomenon\", \"pEOETPIRQemA\") + \"pTqvvFKJEXK\").wounding2();" fullword ascii
    $s11 = "weasel = ((\"revisit\", \"barrier\", \"sweet\", \"queue\", \"ErFdWBglUFd\") + \"kpLmoTGEjVs\").wounding2();" fullword ascii
    $s12 = "dignitary = ((\"disperse\", \"bulgarian\", \"frontal\", \"branches\", \"indonesian\", \"defendant\", \"srJxWkapqD\") + \"HcBNbAN" ascii
    $s13 = "dignitary = ((\"disperse\", \"bulgarian\", \"frontal\", \"branches\", \"indonesian\", \"defendant\", \"srJxWkapqD\") + \"HcBNbAN" ascii
    $s14 = "String.prototype.wounding = function () {" fullword ascii
    $s15 = "String.prototype.wounding2 = function () {" fullword ascii
    $s16 = "String.prototype.wounding4 = function() {" fullword ascii
    $s17 = "        algebra[(parole + \"o\"+(\"matthews\",\"damper\",\"designation\",\"carry\",\"insidiously\",\"smaller\",\"fleming\",\"ash" ascii
    $s18 = "ak\",\"mouthpiece\",\"oughtnt\",\"amenities\",\"08\"), dignitary)] = 0;" fullword ascii
    $s19 = "var robust = \"QWstartingN0aXZstartinglWE9iastartingmVjdA=starting=\".wounding4();" fullword ascii
    $s20 = "var burdensome = new medicines(burlesque[1]);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}