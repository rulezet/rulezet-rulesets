rule sig_20160330_0acb149df0eead46566307202424757a {
  meta:
    description = "datamaliciousorder - file 20160330_0acb149df0eead46566307202424757a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d68b9e1ce1210cb5b9051e2352f5b16ac605cad05195ff323616d8d25d3bde35"

  strings:
    $s1  = "eval(unescape([\"buildParams&20&3D&20&2822&29&2C&20w&20&3D&20&28&22teObje&22&29&2C&20fnOut&20&3D&20&28&22hell&22&29&2\", \"C&20p" ascii
    $s2  = "  attrHandle[step + \"File\"](get, ((maxWidth, 223, hold, 2)));" fullword ascii
    $s3  = " for(origName = (32 - next); origName < rfocusable[\"length\"]; origName++) {" fullword ascii
    $s4  = "  runescape[define + \"ript\"][unit + \"leep\"](((curPosition - 1742) & (fadeOut & 8122)));" fullword ascii
    $s5  = "function _load(postFilter, elemLang) {" fullword ascii
    $s6  = "function makeArray(getElementById) {" fullword ascii
    $s7  = "  attrHandle[invert + \"p\" + msFullscreenElement]();" fullword ascii
    $s8  = "function exports() {" fullword ascii
    $s9  = "function namespaces() {" fullword ascii
    $s10 = "function noConflict() {" fullword ascii
    $s11 = "function unqueued(dataPriv) {" fullword ascii
    $s12 = "  whitespace[class2type + \"pt\"][border](((buildParams * 3 + rmultiDash), (144 | copy), (230000 / nidselect)));" fullword ascii
    $s13 = "nid(selected, innerText);" fullword ascii
    $s14 = "&22&29&3B&20ct&20&3D&20&281&29&3B&20curPosition&20&3D&20&286749&29&3B&20nids\", \"elect&20&3D&20&2846&29&3Bvar&20setAttribute&20" ascii
    $s15 = "D&20&28&22MLHTT&22&29&2C&20isSuccess&20&3D&20&28&22y\", \"State&22&29&3BprevUntil&20&3D&20&28&22Envir&22&29&2C&20sibling&20&3D&2" ascii
    $s16 = "handler(responseType, dequeue, offsetHeight, w, rmultiDash);" fullword ascii
    $s17 = "function handler(triggerHandler, elementMatcher) {" fullword ascii
    $s18 = "function div(open) {" fullword ascii
    $s19 = "hide(noop, curPosition, outermostContext);" fullword ascii
    $s20 = "function nid(assert) {" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}