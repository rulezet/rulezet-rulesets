rule sig_20160518_2ff43960f132355cd8fa5670695c78e1 {
  meta:
    description = "datamaliciousorder - file 20160518_2ff43960f132355cd8fa5670695c78e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0ae9ca694ce30377d13927e7bb3c24af0e44bdbffc2e2bf5da4a1b578d78c17"

  strings:
    $s1  = "var pounce = [betaken, brewery,vertex,  \"\"+\".\"+(\"dugout\",\"creates\",\"maltreated\",\"literary\",\"associating\",\"violati" ascii
    $s2  = "            realize[suites]((\"forte\",\"trigonometry\",\"G\" + weasel) + (\"dialog\",\"evoke\",\"bingo\",\"hospitals\",\"T\"), " ascii
    $s3  = "var rebates=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".namibia4())&&realize[\"c3RhdHVz\".namibia4()] +\"\"==\"MjAw\".namibi" ascii
    $s4  = "var rebates=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".namibia4())&&realize[\"c3RhdHVz\".namibia4()] +\"\"==\"MjAw\".namibi" ascii
    $s5  = "northeastern = northeastern+ pounce.shift();" fullword ascii
    $s6  = "inexpensive = ((\"babble\", \"reasoning\", \"intriguing\", \"impaled\", \"pblOIJhBtVa\") + \"rsbVYsuHT\").namibia2();" fullword ascii
    $s7  = "weasel = ((\"liberation\", \"defines\", \"atmosphere\", \"pandemonium\", \"EWdVpvo\") + \"dDsztggXyLp\").namibia2();" fullword ascii
    $s8  = "sealed(\"aHR0cDovLw==\".namibia4()+\"\\u0066\\u0065\\u0065\\u0064\\u0063\\u006F\\u006E\\u0073\\u0075\\u006D\\u0065\\u0072\\u002E" ascii
    $s9  = "var portend = gnarled[pounce.shift()](pounce.shift());" fullword ascii
    $s10 = "String.prototype.namibia2 = function () {" fullword ascii
    $s11 = "String.prototype.namibia = function () {" fullword ascii
    $s12 = "String.prototype.namibia4 = function() {" fullword ascii
    $s13 = "        var northeastern = portend + \"/\" + morocco ;" fullword ascii
    $s14 = "var pounce = [betaken, brewery,vertex,  \"\"+\".\"+(\"dugout\",\"creates\",\"maltreated\",\"literary\",\"associating\",\"violati" ascii
    $s15 = "extended = \"_F2_\";" fullword ascii
    $s16 = "var artless = {" fullword ascii
    $s17 = "chandelier = this;" fullword ascii
    $s18 = "var brewery =\"RXhwYW5diamondskRW52aXdiamondsJvbm1lbnRTdHJdiamondspbmdz\".namibia4();" fullword ascii
    $s19 = "var gnarled = new vestry(productions[1]);" fullword ascii
    $s20 = "var vestry = this[pounce.shift()];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}