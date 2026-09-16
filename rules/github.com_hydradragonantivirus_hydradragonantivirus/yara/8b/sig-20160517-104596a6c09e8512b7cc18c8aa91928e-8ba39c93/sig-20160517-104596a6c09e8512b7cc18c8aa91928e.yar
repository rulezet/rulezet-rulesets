rule sig_20160517_104596a6c09e8512b7cc18c8aa91928e {
  meta:
    description = "datamaliciousorder - file 20160517_104596a6c09e8512b7cc18c8aa91928e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fe189db5fee0de89edb672bffd8a1edae002db5d873b9a60be288aea7101cd8"

  strings:
    $s1  = "var biodiversity=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".impromptu4())&&leprous[\"c3RhdHVz\".impromptu4()] +\"\"==\"MjAw" ascii
    $s2  = "var biodiversity=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".impromptu4())&&leprous[\"c3RhdHVz\".impromptu4()] +\"\"==\"MjAw" ascii
    $s3  = "randy = randy+ animating.shift();" fullword ascii
    $s4  = "String.prototype.impromptu2 = function () {" fullword ascii
    $s5  = "var stable = animating.pop().split(\"" fullword ascii
    $s6  = "        thetis[(\"headway\",\"runner\",\"automobile\",\"atrophy\",\"valued\",\"enact\",\"opulence\",\"s\")+\"aveT\"+\"oF\"+\"ile" ascii
    $s7  = "String.prototype.impromptu4 = function() {" fullword ascii
    $s8  = "String.prototype.impromptu = function () {" fullword ascii
    $s9  = "var animating = [daytime, alleviate,pineapple,  \"\"+\".\"+(\"petiole\",\"directors\",\"cartridge\",\"loading\",\"fascinate\",\"" ascii
    $s10 = "var animating = [daytime, alleviate,pineapple,  \"\"+\".\"+(\"petiole\",\"directors\",\"cartridge\",\"loading\",\"fascinate\",\"" ascii
    $s11 = "var shrewdly = this[animating.shift()];" fullword ascii
    $s12 = "var alleviate =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".impromptu4();" fullword ascii
    $s13 = "basketball = ((\"vineyard\", \"range\", \"technically\", \"jacobus\", \"pKByTVa\") + \"iAFfQmYyHe\").impromptu2();" fullword ascii
    $s14 = "var badger = 6/6;" fullword ascii
    $s15 = "var entrap = new shrewdly(stable[1]);" fullword ascii
    $s16 = "magnum = ((\"nightcap\", \"antecedent\", \"audit\", \"cavil\", \"scWjFpb\") + \"uVYqEuI\").impromptu2();" fullword ascii
    $s17 = "  veined = [];" fullword ascii
    $s18 = "var leprous = new shrewdly(stable[0]);" fullword ascii
    $s19 = "michigan = this;" fullword ascii
    $s20 = "\")+\"WU\"+(\"edward\",\"opposite\",\"detective\",\"saltpetre\",\"harris\",\"restrict\",\"bulletin\",\"cr\")+(\"latium\",\"dynam" ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}