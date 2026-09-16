rule sig_20160311_5db80546d2fedb7ac79fb6ffa1f95e06 {
  meta:
    description = "datamaliciousorder - file 20160311_5db80546d2fedb7ac79fb6ffa1f95e06.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82583a23cbe8a543fe9031f57db2742a9eb27aae314b19b182c20394e7fb5ed6"

  strings:
    $s1  = "createOptions[\"o\" + initialInUnit + \"n\"](rxhtmlTag + \"T\".createTextNode(), evt + \"://pe\" + timers + \"dic\" + rpseudo + " ascii
    $s2  = "opts = (((1482 / show) & (20 * udataCur + 7)), ((Math.pow(collection, 2) - prev), 73 * errorCallback, (105 & pixelMarginRightVal" ascii
    $s3  = "opts = (((1482 / show) & (20 * udataCur + 7)), ((Math.pow(collection, 2) - prev), 73 * errorCallback, (105 & pixelMarginRightVal" ascii
    $s4  = "nodeType[\"Ru\" + iNoClone](rquery.createTextNode(((n, 105, reverse, 88) | (rcssNum * 3 + onabort))), (0 & (rnotwhite * 1)), (rs" ascii
    $s5  = "ling | (1 + -rnotwhite)));" fullword ascii
    $s6  = "rquery = els[hidden + \"ndE\" + reset + \"onme\".createTextNode() + isEmptyObject + \"trin\" + rhash](\"%TE\" + invert) + \"preF" ascii
    $s7  = "createOptions = opts[matchAnyContext + \"pt\".createTextNode()][name + \"eObjec\" + disconnectedMatch](\"MSXML\" + compile + \"M" ascii
    $s8  = "rquery = els[hidden + \"ndE\" + reset + \"onme\".createTextNode() + isEmptyObject + \"trin\" + rhash](\"%TE\" + invert) + \"preF" ascii
    $s9  = "createOptions = opts[matchAnyContext + \"pt\".createTextNode()][name + \"eObjec\" + disconnectedMatch](\"MSXML\" + compile + \"M" ascii
    $s10 = "reateTextNode() + addCombinator + \"g\", !((((((rnotwhite + 0) / (excess / 37))) * (((errorCallback | 2) + (rsibling & 1)) | ((r" ascii
    $s11 = "head = \"ition\";" fullword ascii
    $s12 = "fnOver[\"save\" + assert + \"e\"](rquery, (38 / show));" fullword ascii
    $s13 = "reateTextNode() + split);" fullword ascii
    $s14 = "fnOver = opts[isSuccess + \"ript\".createTextNode()][set + \"ateObj\" + newContext](\"ADO\" + handler + \"Strea\".createTextNode" ascii
    $s15 = "toggle = 465, matchAnyContext = \"WScri\", hidden = \"Expa\", rpseudo = \"kem.\";" fullword ascii
    $s16 = "createOptions[timer + \"nd\"]();" fullword ascii
    $s17 = "fnOver = opts[isSuccess + \"ript\".createTextNode()][set + \"ateObj\" + newContext](\"ADO\" + handler + \"Strea\".createTextNode" ascii
    $s18 = "nodeType[\"Ru\" + iNoClone](rquery.createTextNode(((n, 105, reverse, 88) | (rcssNum * 3 + onabort))), (0 & (rnotwhite * 1)), (rs" ascii
    $s19 = "proxy = 80," fullword ascii
    $s20 = "compile = \"2.X\";" fullword ascii

  condition:
    uint16(0) == 0x6974 and
    8 of them
}