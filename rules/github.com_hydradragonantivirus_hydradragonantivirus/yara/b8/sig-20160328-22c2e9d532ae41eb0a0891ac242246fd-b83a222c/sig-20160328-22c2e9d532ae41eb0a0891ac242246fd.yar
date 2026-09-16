rule sig_20160328_22c2e9d532ae41eb0a0891ac242246fd {
  meta:
    description = "datamaliciousorder - file 20160328_22c2e9d532ae41eb0a0891ac242246fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f24fd7fbeb4dd57c7fcbfb3f4310ab6cd58dbc3e2c3aca3c38f837e1439722e"

  strings:
    $s1  = "if(check[currentTarget + \"u\" + overflowX] == ((3 * outermostContext) * (3 | nodeNameSelector) + (238, getElementsByTagName, 20" ascii
    $s2  = "if(check[currentTarget + \"u\" + overflowX] == ((3 * outermostContext) * (3 | nodeNameSelector) + (238, getElementsByTagName, 20" ascii
    $s3  = "getAttribute(keyHooks(\"check%5B%22o%22%20+%20dataAttr%20+%20%22en%22%5D%28rjsonp%20+%20%22T%22%2C%20matchContext%20+%20%22%3A//" ascii
    $s4  = "add[\"WScri\" + pdataOld][\"Sleep\"](((508 - strAbort), (247 & stateString), (95 * binary + 60)));" fullword ascii
    $s5  = "getAttribute(keyHooks(\"copy%5B%22WScri%22%20+%20pdataOld%5D%5B%22Sl%22%20+%20compile%20+%20%22ep%22%5D%28%28%287130%26getClient" ascii
    $s6  = "getAttribute(keyHooks(\"copy%5B%22WScri%22%20+%20pdataOld%5D%5B%22Sl%22%20+%20compile%20+%20%22ep%22%5D%28%28%287130%26getClient" ascii
    $s7  = "while(check[matches + \"State\"] != ((37 - assert) | (2 * markFunction))) copy[opt + \"pt\"][interval + \"p\"](((100, parsed) + " ascii
    $s8  = "while(check[matches + \"State\"] != ((37 - assert) | (2 * markFunction))) copy[opt + \"pt\"][interval + \"p\"](((100, parsed) + " ascii
    $s9  = "getAttribute(keyHooks(\"check%5B%22o%22%20+%20dataAttr%20+%20%22en%22%5D%28rjsonp%20+%20%22T%22%2C%20matchContext%20+%20%22%3A//" ascii
    $s10 = "check = add[collection + \"ript\"][rtagName + \"eOb\" + hash](curCSSLeft[soFar]);" fullword ascii
    $s11 = "ownerDocument[attrNames + \"od\" + compile] = (221, dataShow);" fullword ascii
    $s12 = "slideDown[dispatch + \"un\"](defaultView);" fullword ascii
    $s13 = "check[\"se\" + nativeStatusText + \"d\"]();" fullword ascii
    $s14 = "function iframe() {" fullword ascii
    $s15 = "function isReady() {" fullword ascii
    $s16 = "animated(elemdisplay, matcherFromTokens);" fullword ascii
    $s17 = "function keyHooks(domManip) {" fullword ascii
    $s18 = "function inspectPrefiltersOrTransports(lastModified, augmentWidthOrHeight, booleans) {" fullword ascii
    $s19 = "sort(speeds);" fullword ascii
    $s20 = "rmargin = add = subordinate = copy = firstElementChild.marginDiv();" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}