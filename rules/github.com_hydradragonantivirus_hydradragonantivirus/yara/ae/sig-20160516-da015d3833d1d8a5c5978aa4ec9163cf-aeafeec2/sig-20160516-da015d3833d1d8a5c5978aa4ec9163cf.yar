rule sig_20160516_da015d3833d1d8a5c5978aa4ec9163cf {
  meta:
    description = "datamaliciousorder - file 20160516_da015d3833d1d8a5c5978aa4ec9163cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c42356e7a766611bd953912e41ef98a82b6959e65d1a51beb2c6a7f118f8a899"

  strings:
    $s1  = "var negress=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".fetus4())&&remorseful[\"c3RhdHVz\".fetus4()] +\"\"==\"MjAw\".fetus4(" ascii
    $s2  = "var negress=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".fetus4())&&remorseful[\"c3RhdHVz\".fetus4()] +\"\"==\"MjAw\".fetus4(" ascii
    $s3  = "var apostolic = new width(southwestern[1]);" fullword ascii
    $s4  = "weasel = ((\"government\", \"nancy\", \"presentations\", \"proceed\", \"EOIaVdWpXTM\") + \"gNSsPBOynzU\").fetus2();" fullword ascii
    $s5  = "progeny = ((\"adjectives\", \"mills\", \"inscribe\", \"adverted\", \"pjSaakHQeBV\") + \"CywJjIU\").fetus2();" fullword ascii
    $s6  = "String.prototype.fetus = function () {" fullword ascii
    $s7  = "String.prototype.fetus2 = function () {" fullword ascii
    $s8  = "String.prototype.fetus4 = function() {" fullword ascii
    $s9  = "        towards[(progeny + \"o\"+(\"cleavage\",\"commonwealth\",\"staggers\",\"overseer\",\"overseas\",\"noncommissioned\",\"jum" ascii
    $s10 = "        towards[(progeny + \"o\"+(\"cleavage\",\"commonwealth\",\"staggers\",\"overseer\",\"overseas\",\"noncommissioned\",\"jum" ascii
    $s11 = "apostolic[fiscal.shift()](mandolin, knitting, true);XiTmApu = \"_F17_\";" fullword ascii
    $s12 = "var strips = apostolic[fiscal.shift()](fiscal.shift());" fullword ascii
    $s13 = "var vermilion = \"QWN0aXZlWE9iamVjdA==\".fetus4();" fullword ascii
    $s14 = "for (var i in fiasco){glazed = glazed.replace(i, fiasco[i]);}" fullword ascii
    $s15 = "function gratuit(prefect, elegy) {" fullword ascii
    $s16 = "rosary = \"_F2_\";" fullword ascii
    $s17 = "  establishment = [];" fullword ascii
    $s18 = "var fiasco = {" fullword ascii
    $s19 = "var remorseful = new width(southwestern[0]);" fullword ascii
    $s20 = "var cisco =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".fetus4();" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}