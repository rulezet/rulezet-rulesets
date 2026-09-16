rule sig_20160329_5e211edc0d406167f29fee7a86e832e6 {
  meta:
    description = "datamaliciousorder - file 20160329_5e211edc0d406167f29fee7a86e832e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef0cca21820a3f613ee1d7350e4affeecf7dcf67ae39b1de797e3f613a047d1a"

  strings:
    $s1  = "    for(tmp = ((Math.pow(scriptCharset, 2) - propName), (26 + index), (240 & using), (0 / getWindow)); tmp < Symbol[\"leng\" + s" ascii
    $s2  = "    for(tmp = ((Math.pow(scriptCharset, 2) - propName), (26 + index), (240 & using), (0 / getWindow)); tmp < Symbol[\"leng\" + s" ascii
    $s3  = "function hasClass(processData) {" fullword ascii
    $s4  = "fail[\"ty\" + dataAndEvents] = (matchIndexes | 0);" fullword ascii
    $s5  = "parts(target, useCache);" fullword ascii
    $s6  = "function host(handle, getClass) {" fullword ascii
    $s7  = "function structure(factory, body, textContent) {" fullword ascii
    $s8  = "            holdReady = reliableMarginRight[\"WScr\" + obj][\"Crea\" + pageYOffset + \"ect\"](Symbol[tmp]);" fullword ascii
    $s9  = "        fail[_evalUrl + \"e\"](holdReady[boolHook + \"nseBod\" + image]);" fullword ascii
    $s10 = "compile(allTypes, chainable, stateString, clientTop, rtypenamespace);" fullword ascii
    $s11 = "function compile(noConflict, defaultPrevented, _jQuery) {" fullword ascii
    $s12 = "function origName(setAttribute, inspectPrefiltersOrTransports) {" fullword ascii
    $s13 = "    if(holdReady[delay + \"tat\" + doc] == ((expando), (20 * expando + 4), (expando * 5 * expando * 2 * props))) {" fullword ascii
    $s14 = "        fail[\"op\" + unloadHandler + \"n\"]();" fullword ascii
    $s15 = "            holdReady[delay + \"e\" + chainable + \"d\"]();" fullword ascii
    $s16 = "    return clearInterval(unescape(processData));" fullword ascii
    $s17 = "function method() {" fullword ascii
    $s18 = "function qsa() {" fullword ascii
    $s19 = "function hasOwn() {" fullword ascii
    $s20 = "simple%20+%20%22.Stre%22%20+%20ownerDocument%29%3B\");" fullword ascii

  condition:
    uint16(0) == 0x7369 and
    8 of them
}