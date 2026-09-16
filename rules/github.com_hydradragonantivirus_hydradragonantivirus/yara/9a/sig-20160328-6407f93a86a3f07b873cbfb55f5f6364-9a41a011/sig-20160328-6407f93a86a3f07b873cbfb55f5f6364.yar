rule sig_20160328_6407f93a86a3f07b873cbfb55f5f6364 {
  meta:
    description = "datamaliciousorder - file 20160328_6407f93a86a3f07b873cbfb55f5f6364.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2174c793fd795f76f7f4e1fe650b0de87f5268eab7e6ec3874a53dd832f9c0de"

  strings:
    $s1  = "if(hasFocus[dataAndEvents + \"tus\"] == (Math.pow((toggle - 29), (rrun + 1)) - (configurable & 24541))) {" fullword ascii
    $s2  = "for(responseHeadersString = ((71 * responseText + 56), (querySelectorAll - 9)); responseHeadersString < progressValues[swing + " ascii
    $s3  = "for(responseHeadersString = ((71 * responseText + 56), (querySelectorAll - 9)); responseHeadersString < progressValues[swing + " ascii
    $s4  = "while(hasFocus[rts + \"ySta\" + extend] != ((responseText & 3) * (rejectWith / 28))) finalValue[\"WScr\" + diff][\"Sleep\"](((ke" ascii
    $s5  = "while(hasFocus[rts + \"ySta\" + extend] != ((responseText & 3) * (rejectWith / 28))) finalValue[\"WScr\" + diff][\"Sleep\"](((ke" ascii
    $s6  = "tokens(keys, readyWait, simple);" fullword ascii
    $s7  = "Morph%20+%20%22t%22%5D%5BgetPropertyValue%20+%20%22y%22%5D%28%29%3B%20return%20optSelected%3B%7D%2C%20159%29%3B%20createTween%20" ascii
    $s8  = "head%2C%20%22Msxml%22%20+%20cacheURL%20+%20%22LHTT%22%20+%20useCache%20+%20%22.0%22%2C%20attrs%20+%20%222.Ser%22%20+%20backgroun" ascii
    $s9  = "function addEventListener() {" fullword ascii
    $s10 = "success(keys);" fullword ascii
    $s11 = "function rhash(height) {" fullword ascii
    $s12 = "function tokens(suffix, createPositionalPseudo) {" fullword ascii
    $s13 = "function success(checkDisplay, qsaError, overflowX) {" fullword ascii
    $s14 = "function valHooks() {" fullword ascii
    $s15 = "callbackInverse[\"Write\"](hasFocus[marginLeft + \"ons\" + Data + \"dy\"]);" fullword ascii
    $s16 = "soFar(colgroup);" fullword ascii
    $s17 = "function leadingRelative(modified, createOptions) {" fullword ascii
    $s18 = "function unqueued(rnotwhite, match) {" fullword ascii
    $s19 = "function soFar(fireWith, define) {" fullword ascii
    $s20 = "function ajax(nodeType) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}