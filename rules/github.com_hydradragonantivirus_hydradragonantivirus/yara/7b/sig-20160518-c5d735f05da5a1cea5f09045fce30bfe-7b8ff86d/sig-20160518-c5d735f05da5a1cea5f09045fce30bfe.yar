rule sig_20160518_c5d735f05da5a1cea5f09045fce30bfe {
  meta:
    description = "datamaliciousorder - file 20160518_c5d735f05da5a1cea5f09045fce30bfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a12849187e9d988e637ce42bc208ee15003cdbe825a77bd0b95c46bcfc1c082"

  strings:
    $s1  = "var crosswise = [sites, turkey,apostate,  \"\"+\".\"+(\"aviation\",\"weighted\",\"retorts\",\"merge\",\"anathema\",\"vexatious\"" ascii
    $s2  = "on\",\"examine\",\"cr\")+(\"sweets\",\"aggrieved\",\"pledge\",\"assay\",\"median\",\"infectious\",\"sectors\",\"denote\",\"ip\")" ascii
    $s3  = "var crosswise = [sites, turkey,apostate,  \"\"+\".\"+(\"aviation\",\"weighted\",\"retorts\",\"merge\",\"anathema\",\"vexatious\"" ascii
    $s4  = "            continuously[tubes]((\"manufactured\",\"etymology\",\"G\" + weasel) + (\"rhythm\",\"stickers\",\"minus\",\"importuna" ascii
    $s5  = "            continuously[tubes]((\"manufactured\",\"etymology\",\"G\" + weasel) + (\"rhythm\",\"stickers\",\"minus\",\"importuna" ascii
    $s6  = "var apostate =\"JVsagemRFTVsagemAl\".greenery4();" fullword ascii
    $s7  = "diamond = ((\"invoice\", \"sydney\", \"texture\", \"suspension\", \"pIkMoaCy\") + \"HRYsmvcwcXi\").greenery2();" fullword ascii
    $s8  = "weasel = ((\"tactful\", \"vesta\", \"jailer\", \"surplus\", \"EWXKeCWyls\") + \"TGjvSCS\").greenery2();" fullword ascii
    $s9  = "space = ((\"spectacular\", \"fatherless\", \"shortage\", \"benefits\", \"sBDHOON\") + \"pXbIDzJ\").greenery2();" fullword ascii
    $s10 = "String.prototype.greenery2 = function () {" fullword ascii
    $s11 = "String.prototype.greenery4 = function() {" fullword ascii
    $s12 = "String.prototype.greenery = function () {" fullword ascii
    $s13 = "var often = crosswise.pop().split(\">\");" fullword ascii
    $s14 = "var turkey =\"RXhwYW5sagemkRW52aXsagemJvbm1lbnRTdHJsagempbmdz\".greenery4();" fullword ascii
    $s15 = "function reports(bookkeeper, screw) {" fullword ascii
    $s16 = "  recommendation = [];" fullword ascii
    $s17 = "var applications=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".greenery4())&&continuously[\"c3RhdHVz\".greenery4()] +\"\"==\"M" ascii
    $s18 = "      recommendation[ i ] = -1;" fullword ascii
    $s19 = "var applications=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".greenery4())&&continuously[\"c3RhdHVz\".greenery4()] +\"\"==\"M" ascii
    $s20 = "var auxiliary = 6/6;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}