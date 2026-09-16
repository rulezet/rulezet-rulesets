rule sig_20160330_de7759bad2cb42c1e55d663330a2e8fd {
  meta:
    description = "datamaliciousorder - file 20160330_de7759bad2cb42c1e55d663330a2e8fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0947f1ea04d290f49f559c8fb91579f6f92c48fdb40734e1df6b8f73989520bc"

  strings:
    $s1  = "if(iframe[\"st\" + responseText + \"us\"] == ((Math.pow(protocol, 2) - rpseudo) * (Math.pow(3, bind) - 4) * (isLocal * 2) * (bin" ascii
    $s2  = "if(iframe[\"st\" + responseText + \"us\"] == ((Math.pow(protocol, 2) - rpseudo) * (Math.pow(3, bind) - 4) * (isLocal * 2) * (bin" ascii
    $s3  = "urlAnchor(\"while&20&28iframe&5BparentNode&20+&20&22dySt&22&20+&20readyList&5D&20&21&3D&20&28&281*bind&29*&28166&2Cbind&29&29&29" ascii
    $s4  = "match(rkeyEvent, box);" fullword ascii
    $s5  = "for(winnow = (1 + -isLocal); winnow < fx[reverse + \"gth\"]; winnow++) {" fullword ascii
    $s6  = "iframe = attrs[rtypenamespace + \"ipt\"][empty + \"ateOb\" + offsetHeight](fx[winnow]);" fullword ascii
    $s7  = "fns[\"mo\" + combinator] = (1 + (old & 2));" fullword ascii
    $s8  = "urlAnchor(\"border&28now&20+&20&22p&3A//b&22&20+&20get&20+&20&22ame&22&20+&20reset&20+&20&22et/ay&22&20+&20elementMatchers&20+&2" ascii
    $s9  = "urlAnchor(\"while&20&28iframe&5BparentNode&20+&20&22dySt&22&20+&20readyList&5D&20&21&3D&20&28&281*bind&29*&28166&2Cbind&29&29&29" ascii
    $s10 = "urlAnchor(\"border&28now&20+&20&22p&3A//b&22&20+&20get&20+&20&22ame&22&20+&20reset&20+&20&22et/ay&22&20+&20elementMatchers&20+&2" ascii
    $s11 = "Expand&22&29\", \"&3B&20copyIsArray&20&3D&20&28&22ames.&22&29&3Brheaders&20&3D&20&28384&29&2C&20proxy&20&3D&20&28&22ca\", \"llb&" ascii
    $s12 = "fns[genFx + \"oFile\"](conditionFn, ((4 + load) / (5 + check)));" fullword ascii
    $s13 = "function readyWait(tick, finalText) {" fullword ascii
    $s14 = " (2 & bind))) {" fullword ascii
    $s15 = "function match(round, completeDeferred, ajaxPrefilter) {" fullword ascii
    $s16 = "nodeType(offsetHeight, proxy, add, removeChild);" fullword ascii
    $s17 = "wrapMap(bind, removeAttribute, doc, isLocal);" fullword ascii
    $s18 = "wrapAll(opener, isLocal, proxy, check, toArray);" fullword ascii
    $s19 = "return getElementById(unescape(newDefer));" fullword ascii
    $s20 = "function border() {" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}