rule sig_20160519_24c9526e92ff189afa8c672624fe6f12 {
  meta:
    description = "datamaliciousorder - file 20160519_24c9526e92ff189afa8c672624fe6f12.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bad485b50501dd5cb0121a8ca223bbdcf425082298205ccc0354848bedb3a1f"

  strings:
    $s1  = "        var circulate = elevate + \"/\" + gallon ;" fullword ascii
    $s2  = "circulate = circulate+ precisely.shift();" fullword ascii
    $s3  = "nebulous = ((\"stocks\", \"trespassing\", \"barbaric\", \"clive\", \"swsGVGY\") + \"yIsBHCNq\").retailer2();" fullword ascii
    $s4  = "weasel = ((\"rumble\", \"tatters\", \"rajah\", \"spread\", \"EbrdRCpQrzn\") + \"lNiwAetnS\").retailer2();" fullword ascii
    $s5  = "var repellent=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".retailer4())&&plurality[\"c3RhdHVz\".retailer4()] +\"\"==\"MjAw\"." ascii
    $s6  = "var repellent=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".retailer4())&&plurality[\"c3RhdHVz\".retailer4()] +\"\"==\"MjAw\"." ascii
    $s7  = "var precisely = [jubilee, invest,islet,  \"\"+\".\"+(\"daughterinlaw\",\"metaphorical\",\"arrant\",\"demented\",\"huddle\",\"dou" ascii
    $s8  = "recovered[precisely.shift()](circulate, marrow, true);" fullword ascii
    $s9  = "var elevate = recovered[precisely.shift()](precisely.shift());" fullword ascii
    $s10 = "jingle = ((\"axiom\", \"bargain\", \"plastered\", \"aurora\", \"pAqmHtad\") + \"XVxahy\").retailer2();" fullword ascii
    $s11 = "String.prototype.retailer4 = function() {" fullword ascii
    $s12 = "var recovered = new compare(vouchsafe[1]);" fullword ascii
    $s13 = "var plurality = new compare(vouchsafe[0]);" fullword ascii
    $s14 = "String.prototype.retailer2 = function () {" fullword ascii
    $s15 = "var compare = this[precisely.shift()];" fullword ascii
    $s16 = "String.prototype.retailer = function () {" fullword ascii
    $s17 = "var vouchsafe = precisely.pop().split(\">\");" fullword ascii
    $s18 = "tasting = \"_F2_\";" fullword ascii
    $s19 = "leasing = this;" fullword ascii
    $s20 = "var marrow = 6/6;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}