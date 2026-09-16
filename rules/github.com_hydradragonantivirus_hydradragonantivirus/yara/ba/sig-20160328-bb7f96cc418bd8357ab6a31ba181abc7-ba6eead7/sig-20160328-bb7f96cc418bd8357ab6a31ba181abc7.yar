rule sig_20160328_bb7f96cc418bd8357ab6a31ba181abc7 {
  meta:
    description = "datamaliciousorder - file 20160328_bb7f96cc418bd8357ab6a31ba181abc7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da48cf93dfeecef4242ae4bf8cc43b33c4e8d528ecf140ca0f15baeb1d2e9e8b"

  strings:
    $s1  = "eval(toggle(\"var%20_evalUrl%20%3D%20%28%22uctor%22%29%2C%20close%20%3D%20%282905%29%2C%20isBorderBox%20%3D%20%2845%29%3Bvar%20m" ascii
    $s2  = "end[\"mo\" + gotoEnd] = ((7 - getResponseHeader) & (30 - delegate));" fullword ascii
    $s3  = "    if (winnow[getter] == ((Math.pow(26, hold) - 642) + (properties / 33))) {" fullword ascii
    $s4  = "    while (winnow[simulate + \"Sta\" + addCombinator] != (Math.pow((promise, 44, evt), (1 * hold)) - (5 + rsubmitterTypes))) dis" ascii
    $s5  = "    while (winnow[simulate + \"Sta\" + addCombinator] != (Math.pow((promise, 44, evt), (1 * hold)) - (5 + rsubmitterTypes))) dis" ascii
    $s6  = "    parse(toggle(\"dataShow%28always%20+%20%22/cha%22%20+%20xhrSuccessStatus%20+%20%22ary%22%20+%20noCloneChecked%20+%20%22rcia%" ascii
    $s7  = "    parse(toggle(\"fail%20%3D%20%5B%22Msx%22%20+%20adjustCSS%20+%20%22rver%22%20+%20deep%20+%20%22TP.6.0%22%2C%20handle%20+%20%2" ascii
    $s8  = "vent%20%3D%20%28%22Ru%22%29%2C%20currentTime%20%3D%20%2832%29%2C%20rscriptType%20%3D%20%28%22se%22%29%2C%20setPositiveNumber%20%" ascii
    $s9  = "function beforeunload(rfxtypes, attrs, responseHeadersString) {" fullword ascii
    $s10 = "            winnow[rscriptType + \"nd\"]();" fullword ascii
    $s11 = "le[\"WScri\" + createButtonPseudo][\"Sle\" + matcherIn + \"p\"](((5 * hold * 2 * unique) & (7 * hold * 3 * evt)));" fullword ascii
    $s12 = "function nodeType(exports) {" fullword ascii
    $s13 = "    parse(toggle(\"callbackName%20%3D%20soFar%5B%22Exp%22%20+%20getClientRects%20+%20%22viron%22%20+%20hasDuplicate%20+%20%22Str" ascii
    $s14 = "    for (isXML = (0 / (rfocusMorph, 127, detach)); isXML < fail[\"len\" + suffix + \"t\" + selected]; isXML++) {" fullword ascii
    $s15 = "            winnow = disable[\"WSc\" + off][\"Create\" + func + \"t\"](fail[isXML]);" fullword ascii
    $s16 = "        } catch (currentTarget) {}" fullword ascii
    $s17 = "function scale(params, byElement, addGetHookIf) {" fullword ascii
    $s18 = "function calculatePosition(textContent, matches) {" fullword ascii
    $s19 = "function siblingCheck() {" fullword ascii
    $s20 = "function dataShow() {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}