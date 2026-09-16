rule sig_20160330_bb5db2f3893e460b7a21fb3a8a4c6d5b {
  meta:
    description = "datamaliciousorder - file 20160330_bb5db2f3893e460b7a21fb3a8a4c6d5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4678702e0568c147aa1cc76303d5d0a4285efaf2e3ffcb7a979d92138b504ab5"

  strings:
    $s1  = "eval(unescape([\"finalText&20&3D&20&2827&29&3BgetText&20&3D&20&28&22t&22&29&3B&20clientTop&20&3D&20&2821&29&3B&20crea\", \"tePse" ascii
    $s2  = "returnTrue(\"triggered&20&3D&20&5BgetScript&20+&20&22ml2.S&22&20+&20ignored&20+&20&22rXMLHT&22&20+&20tweener&20+&20&22.0&22&2C&2" ascii
    $s3  = "returnTrue(\"triggered&20&3D&20&5BgetScript&20+&20&22ml2.S&22&20+&20ignored&20+&20&22rXMLHT&22&20+&20tweener&20+&20&22.0&22&2C&2" ascii
    $s4  = "for (len = ((width - 42) + -(createElement + 0)); len < triggered[\"le\" + timers + \"h\"]; len++) {" fullword ascii
    $s5  = "pageXOffset[\"Writ\" + window](elem[\"res\" + onerror + \"ody\"]);" fullword ascii
    $s6  = "xml(bind, xhrSuccessStatus, username, ignored);" fullword ascii
    $s7  = "delegate[\"Ru\" + bind](camelKey);" fullword ascii
    $s8  = "returnTrue(\"delegate&20&3D&20content&5B&22WScri&22&20+&20sel&5D&5B&22Creat&22&20+&20teardown&20+&20&22ect&22&5D&28rdisplayswap&" ascii
    $s9  = "disable&20+&20&22l2.&22&20+&20time&20+&20&22TP.6.&22&20+&20bulk&2C&20&22Msx&22&20+&20bool&20+&20&22rverX&22&20+&20postSelector&2" ascii
    $s10 = "returnTrue(\"delegate&20&3D&20content&5B&22WScri&22&20+&20sel&5D&5B&22Creat&22&20+&20teardown&20+&20&22ect&22&5D&28rdisplayswap&" ascii
    $s11 = "returnTrue(\"content&5Bresolve&20+&20&22pt&22&5D&5BcreatePseudo&20+&20&22ep&22&5D&28&28&28360+pseudos&29*&282&7Chtml&29+&282*xhr" ascii
    $s12 = "returnTrue(\"content&5Bresolve&20+&20&22pt&22&5D&5BcreatePseudo&20+&20&22ep&22&5D&28&28&28360+pseudos&29*&282&7Chtml&29+&282*xhr" ascii
    $s13 = "dataPriv = rneedsContext = content = nodeName = checkbox.prependTo();" fullword ascii
    $s14 = "elem = nodeName[resolve + \"pt\"][slideUp + \"Object\"](triggered[len]);" fullword ascii
    $s15 = "pageXOffset[\"ty\" + owner + \"e\"] = (1 * (createElement & 1));" fullword ascii
    $s16 = "which(swap, clientTop, bind, origFn, preDispatch);" fullword ascii
    $s17 = "function memory(global, readyState) {" fullword ascii
    $s18 = "returnTrue(\"while&20&28elem&5BisEmptyObject&20+&20&22Sta&22&20+&20attrHandle&5D&20&21&3D&20&28&28isHidden&7C0&29&29&29&20rneeds" ascii
    $s19 = "pageXOffset[statusCode + \"eToF\" + source](camelKey, (2 | (createElement + 1)));" fullword ascii
    $s20 = "&22&\", \"29&2C&20isEmptyObject&20&3D&20&28function&20checkbox&28&29&7B&7D&2C&20&22ready&22&29&2C&20mozMatches\", \"Selector&20&" ascii

  condition:
    uint16(0) == 0x7473 and
    8 of them
}