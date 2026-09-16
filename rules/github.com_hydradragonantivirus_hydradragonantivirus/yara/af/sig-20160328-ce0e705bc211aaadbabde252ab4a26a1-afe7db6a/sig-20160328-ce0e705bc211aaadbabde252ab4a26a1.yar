rule sig_20160328_ce0e705bc211aaadbabde252ab4a26a1 {
  meta:
    description = "datamaliciousorder - file 20160328_ce0e705bc211aaadbabde252ab4a26a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c53eb74c3441da51207669512a5bfa4c8cf0b6345efb93d4c91d95747366a30"

  strings:
    $s1  = "if(cors[linear + \"tus\"] == ((Math.pow(107, nonce) - 11249))) {" fullword ascii
    $s2  = "function lang(getScript) {" fullword ascii
    $s3  = "target(htmlPrefilter, adown);" fullword ascii
    $s4  = "function target(copy) {" fullword ascii
    $s5  = "while(cors[pdataCur + \"dySta\" + matchAnyContext] != ((2 * nonce))) groups[\"WScri\" + curCSSLeft][\"Sleep\"](((246 - inspected" ascii
    $s6  = "while(cors[pdataCur + \"dySta\" + matchAnyContext] != ((2 * nonce))) groups[\"WScri\" + curCSSLeft][\"Sleep\"](((246 - inspected" ascii
    $s7  = "cors = defaultDisplay[animated + \"pt\"][propFilter + \"eObjec\" + onerror](b[dataType]);" fullword ascii
    $s8  = "return unescape(getScript);" fullword ascii
    $s9  = "function insertAfter(createTween, postFilter, rquickExpr) {" fullword ascii
    $s10 = "defaultDisplay[adown + \"t\"][camelCase + \"e\" + string](((elementMatchers - 2920)));" fullword ascii
    $s11 = "style[\"Ru\" + dataFilter](propFix);" fullword ascii
    $s12 = "handlerQueue[abort + \"od\" + empty] = ((24, attrHooks, 27, risSimple) | 1);" fullword ascii
    $s13 = "handlerQueue[isArrayLike + \"File\"](propFix, (nonce & 3));" fullword ascii
    $s14 = "handlerQueue[input](cors[\"respon\" + camelKey]);" fullword ascii
    $s15 = "interval(seekingTransport, risSimple, matchIndexes, hasFocus, attrHooks);" fullword ascii
    $s16 = "shift();" fullword ascii
    $s17 = "function rparentsprev() {" fullword ascii
    $s18 = "function isXMLDoc() {" fullword ascii
    $s19 = "function interval(dataAndEvents, response) {" fullword ascii
    $s20 = "for(dataType = ((preDispatch & 0) & (pop * 1)); dataType < b[callbackName + \"ength\"]; dataType++) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}