rule sig_20160330_19784b98d55eea5e1022de4dea4f74a6 {
  meta:
    description = "datamaliciousorder - file 20160330_19784b98d55eea5e1022de4dea4f74a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "079e0437508aaf7499b14d3e504d395776672dc3eaa2bf7b8adaea7bc86b5094"

  strings:
    $x1  = "eval(unescape([\"var&20responseContainer&20&3D&20&28&22ateO&22&29&2C&20rmsPrefix&20&3D&20&284&29&3Biterator&20&3D&20&\", \"28&22" ascii
    $s2  = "    clientTop(\"selector&5B&22op&22&20+&20p&20+&20&22n&22&5D&28getElementById&20+&20&22T&22&2C&20radio&20+&20&22p&3A//as&22&20+&" ascii
    $s3  = "Back&20&3D&20&28&22eObj&22&29&3BcurrentTarget&20&3D&20&28&22tion&22&29&3Brke\", \"yEvent&20&3D&20&28&22t&22&29&2C&20children&20&" ascii
    $s4  = "getById[\"ty\" + document + \"e\"] = ((self / 7) / (which + 30));" fullword ascii
    $s5  = "        num[iterator + \"ipt\"][empty + \"e\" + document](((Math.pow(hasOwn, 2) - removeProp) / (16 | add)));" fullword ascii
    $s6  = "    if (selector[statusCode + \"s\"] == ((tr - 201) | (Math.pow(letterSpacing, 2) - newDefer))) {" fullword ascii
    $s7  = "function headers(maxIterations, rquery, context) {" fullword ascii
    $s8  = "function rparentsprev(attaches, get, base) {" fullword ascii
    $s9  = "    for (rpseudo = ((overflowX / 31) & overflowX); rpseudo < responseHeaders[soFar + \"g\" + attrs]; rpseudo++) {" fullword ascii
    $s10 = "        getById[\"Write\"](selector[clientY + \"seB\" + removeData]);" fullword ascii
    $s11 = "rparentsprev(tfoot, indirect, xhrSupported);" fullword ascii
    $s12 = "function show(documentIsHTML, compiled) {" fullword ascii
    $s13 = "oMatchesSelector(xhrSupported, responseContainer, unmatched, createTween, createTween);" fullword ascii
    $s14 = "function border(exports) {" fullword ascii
    $s15 = "function getStyles(handlerQueue, opt, duplicates) {" fullword ascii
    $s16 = "function tag() {" fullword ascii
    $s17 = "function minWidth() {" fullword ascii
    $s18 = "border();" fullword ascii
    $s19 = "    clientTop(\"selector&5B&22op&22&20+&20p&20+&20&22n&22&5D&28getElementById&20+&20&22T&22&2C&20radio&20+&20&22p&3A//as&22&20+&" ascii
    $s20 = "    clientTop(\"selector&20&3D&20num&5B&22WSc&22&20+&20tfoot&5D&5B&22Cre&22&20+&20responseContainer&20+&20&22bje&22&20+&20clearI" ascii

  condition:
    uint16(0) == 0x616d and
    1 of ($x*) and 4 of them
}