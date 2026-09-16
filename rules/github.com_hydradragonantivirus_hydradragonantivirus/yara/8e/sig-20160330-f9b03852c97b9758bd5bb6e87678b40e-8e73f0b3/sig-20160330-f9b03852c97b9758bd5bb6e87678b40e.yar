rule sig_20160330_f9b03852c97b9758bd5bb6e87678b40e {
  meta:
    description = "datamaliciousorder - file 20160330_f9b03852c97b9758bd5bb6e87678b40e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcfd0e2ac1adca76b21bf841c1da9049822625c4f5bd8e7503b95c0638bc754c"

  strings:
    $s1  = "eval(unescape([\"border&20&3D&20&28&22t&22&29&3Bi&20&3D&20&28&22eBody&22&29&3B&20matcherOut&20&3D&20&2867&29&3B&20isE\", \"mptyO" ascii
    $s2  = "if(outerCache[\"s\" + border + \"atus\"] == (Math.pow((3 * outermostContext * 3), prefix) - (4542 + getElementsByName))) {" fullword ascii
    $s3  = "cacheLength[matcherFromTokens + \"File\"](offsetHeight, ((80 | matcherOut), (178 | defaultPrefilter), (Math.pow(127, prefix) - 1" ascii
    $s4  = "cess&20&3D&20&28&22.Serve&22&29&2C&20propHooks&20&3D&20&281&29&2C&20\", \"wrapInner&20&3D&20&2817&29&2C&20targets&20&3D&20&28&22" ascii
    $s5  = "cacheLength[matcherFromTokens + \"File\"](offsetHeight, ((80 | matcherOut), (178 | defaultPrefilter), (Math.pow(127, prefix) - 1" ascii
    $s6  = "pixelMarginRight(\"qualifier&20&3D&20&5Btargets&20+&20&222.Se&22&20+&20fnOut&20+&20&22MLHTT&22&20+&20appendChild&20+&20&22.0&22&" ascii
    $s7  = "pixelMarginRight(\"qualifier&20&3D&20&5Btargets&20+&20&222.Se&22&20+&20fnOut&20+&20&22MLHTT&22&20+&20appendChild&20+&20&22.0&22&" ascii
    $s8  = "unbind = unmatched = getPropertyValue = step = getClientRects.beforeunload();" fullword ascii
    $s9  = "for(rlocalProtocol = ((13 * prefix) - (1196 / filter)); rlocalProtocol < qualifier[\"length\"]; rlocalProtocol++) {" fullword ascii
    $s10 = "Header&20+&20&22LAY.e&22&20+&20attributes&29&3B\".replace(/&/g, '%'));" fullword ascii
    $s11 = "function timeStamp(risSimple, contentDocument) {" fullword ascii
    $s12 = "function getJSON(preFilters, chainable, eased) {" fullword ascii
    $s13 = "step[\"WScrip\" + border][\"Sleep\"](((3360000 / idx) / (476 / wrapInner)));" fullword ascii
    $s14 = "function dataTypeOrTransport() {" fullword ascii
    $s15 = "el(compile, anim, nodeNameSelector, boxSizingReliableVal);" fullword ascii
    $s16 = "function readyList(l, setMatcher) {" fullword ascii
    $s17 = "pixelMarginRight(\"step&5B_data&20+&20&22ipt&22&5D&5Bdirruns&20+&20&22le&22&20+&20xhrSuccessStatus&5D&28&28&28height/38&29*&28pr" ascii
    $s18 = "function add() {" fullword ascii
    $s19 = "function el() {" fullword ascii
    $s20 = "function fixHooks() {" fullword ascii

  condition:
    uint16(0) == 0x4950 and
    8 of them
}