rule sig_20160330_86ae0d5b0bf551d52f5a16dfb22908ac {
  meta:
    description = "datamaliciousorder - file 20160330_86ae0d5b0bf551d52f5a16dfb22908ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46f464018c31f54d0a25ce9d843b6e200de4e16effeee9b33e92fc45aa9acd17"

  strings:
    $s1  = "eval(unescape([\"fired&20&3D&20&2819&29&3B&20hover&20&3D&20&28&22Save&22&29&3B&20handler&20&3D&20&28&22truc&22&29&3B&\", \"20fil" ascii
    $s2  = " for (addCombinator = ((37 & proxy) - (3 * fireGlobals)); addCombinator < resolveWith[\"le\" + implicitRelative + \"gth\"]; addC" ascii
    $s3  = " for (addCombinator = ((37 & proxy) - (3 * fireGlobals)); addCombinator < resolveWith[\"le\" + implicitRelative + \"gth\"]; addC" ascii
    $s4  = "function manipulationTarget(hooks, throws) {" fullword ascii
    $s5  = "manipulationTarget(add, initial);" fullword ascii
    $s6  = "  apply[\"Write\"](getClientRects[style + \"onseB\" + rdashAlpha]);" fullword ascii
    $s7  = "apply[\"mo\" + headers] = ((19 / fired) + (1 * appendTo));" fullword ascii
    $s8  = "apply[\"t\" + pnum + \"e\"] = (1 & compareDocumentPosition);" fullword ascii
    $s9  = "wrap(curCSSLeft, hasScripts, fireGlobals);" fullword ascii
    $s10 = " dataFilter(\"apply&5Bhover&20+&20&22ToFi&22&20+&20rmultiDash&5D&28contentType&2C&20&28&28appendTo*13*appendTo&29-&2862-testCont" ascii
    $s11 = " dataFilter(\"while&20&28getClientRects&5Bsend&20+&20&22State&22&5D&20&21&3D&20&282*&28appendTo&263&29&29&29&20etag&5BcurCSSLeft" ascii
    $s12 = "function dataFilter(getAllResponseHeaders) {" fullword ascii
    $s13 = " dataFilter(\"apply&5Bhover&20+&20&22ToFi&22&20+&20rmultiDash&5D&28contentType&2C&20&28&28appendTo*13*appendTo&29-&2862-testCont" ascii
    $s14 = "id(hasScripts, proxy, doc, rCRLF);" fullword ascii
    $s15 = " dataFilter(\"while&20&28getClientRects&5Bsend&20+&20&22State&22&5D&20&21&3D&20&282*&28appendTo&263&29&29&29&20etag&5BcurCSSLeft" ascii
    $s16 = "  apply[qsa + \"pe\" + implicitRelative]();" fullword ascii
    $s17 = "  raw[\"WScri\" + guid][\"Sleep\"](((4744 | v) | (3, current)));" fullword ascii
    $s18 = "function innerHTML(addBack, exports) {" fullword ascii
    $s19 = "function id(rootjQuery, push_native) {" fullword ascii
    $s20 = "function optDisabled(ajaxTransport) {" fullword ascii

  condition:
    uint16(0) == 0x706f and
    8 of them
}