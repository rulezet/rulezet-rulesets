rule sig_20160325_5d44c075724663a67e789435e7482422 {
  meta:
    description = "datamaliciousorder - file 20160325_5d44c075724663a67e789435e7482422.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96fff3e34e536b3e6860ee5752920d1bcca7b6ce1b30fb5c8c5641a4fe176f9e"

  strings:
    $s1  = "rsingleTag = (function rxhtmlTag() {}, 36), subordinate = 238, postSelector = 90, scrollLeft = \"o\", propFilter = \"%TEMP%\", r" ascii
    $s2  = "rsingleTag = (function rxhtmlTag() {}, 36), subordinate = 238, postSelector = 90, scrollLeft = \"o\", propFilter = \"%TEMP%\", r" ascii
    $s3  = "eval(parseXML(\"col%28percent%20+%20%22seBod%22%20+%20resolveContexts%2C%20%285*password%26%28Math.pow%2813%2C%20addHandle%29-15" ascii
    $s4  = "eval(parseXML(\"col%28percent%20+%20%22seBod%22%20+%20resolveContexts%2C%20%285*password%26%28Math.pow%2813%2C%20addHandle%29-15" ascii
    $s5  = "elementMatchers = rscriptType[\"Expan\" + ownerDocument + \"onment\" + rtagName + \"ings\"](propFilter + \"/\") + nonce + \"ties" ascii
    $s6  = "rscriptType = bool[\"Creat\" + attrs + \"ct\"](attrHandle + \"ript.\" + container);" fullword ascii
    $s7  = "elementMatchers = rscriptType[\"Expan\" + ownerDocument + \"onment\" + rtagName + \"ings\"](propFilter + \"/\") + nonce + \"ties" ascii
    $s8  = "reset = new getBoundingClientRect[\"Act\" + send + \"Obj\" + tr](\"ADODB.\" + disconnectedMatch + \"am\");" fullword ascii
    $s9  = "bool = getBoundingClientRect[\"WScr\" + extra];" fullword ascii
    $s10 = "password = 3;" fullword ascii
    $s11 = "return groups[responseHeaders](proxy, documentIsHTML);" fullword ascii
    $s12 = "function requestHeaders(proxy, groups, documentIsHTML, responseHeaders) {" fullword ascii
    $s13 = "bool[\"S\" + configurable](((42860 / createOptions) * (2 | image) + (718 & createElement)));" fullword ascii
    $s14 = "iNoClone[qsaError + \"en\" + global]();" fullword ascii
    $s15 = "pipe = \"lance.\";" fullword ascii
    $s16 = "func = \"n\", speed = \"Msxml2\", container = \"Shell\", visible = \"u\", ownerDocument = \"dEnvir\", resolveContexts = \"y\";" fullword ascii
    $s17 = "reset[\"t\" + resolveContexts + \"pe\"] = ((108, returned) & (1 | returned));" fullword ascii
    $s18 = "all = (function rxhtmlTag.hasCompare() {" fullword ascii
    $s19 = "return compareDocumentPosition;" fullword ascii
    $s20 = "strAbort = \"sav\", removeEventListener = \"e\", extra = \"ipt\";" fullword ascii

  condition:
    uint16(0) == 0x616d and
    8 of them
}