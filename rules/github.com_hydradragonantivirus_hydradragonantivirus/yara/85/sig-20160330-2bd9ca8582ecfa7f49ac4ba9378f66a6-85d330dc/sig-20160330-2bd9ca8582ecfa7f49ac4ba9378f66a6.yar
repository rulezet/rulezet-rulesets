rule sig_20160330_2bd9ca8582ecfa7f49ac4ba9378f66a6 {
  meta:
    description = "datamaliciousorder - file 20160330_2bd9ca8582ecfa7f49ac4ba9378f66a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3673b4383ec2a8927175dccc28e0247af14537b0b78eaecadb07604f43ae1d11"

  strings:
    $s1  = "support(\"noCloneChecked&20&3D&20&5Bret&20+&20&22l2.Ser&22&20+&20srcElements&20+&20&22LHT&22&20+&20groups&2C&20&22Msx&22&20+&20r" ascii
    $s2  = "support(\"while&20&28timer&5B&22read&22&20+&20getComputedStyle&20+&20&22ate&22&5D&20&21&3D&20&28&28Math.pow&28originalProperties" ascii
    $s3  = "support(\"while&20&28timer&5B&22read&22&20+&20getComputedStyle&20+&20&22ate&22&5D&20&21&3D&20&28&28Math.pow&28originalProperties" ascii
    $s4  = "for (seed = (0 | (jqXHR - 0)); seed < noCloneChecked[postFilter]; seed++) {" fullword ascii
    $s5  = "if (timer[wrapAll + \"atu\" + fixHook] == ((Math.pow(121, valueIsBorderBox) - 14449) | (offset + 1))) {" fullword ascii
    $s6  = "removeData[\"WScrip\" + finalText][\"Sleep\"](((6140 & forward) & (7146 & end)));" fullword ascii
    $s7  = "function script(load, exports, nodeValue) {" fullword ascii
    $s8  = "support(\"whitespace&28&22http&3A&22&20+&20globalEval&20+&20&22esun&22&20+&20cssExpand&20+&20&22rs.&22&20+&20global&20+&20&22jip" ascii
    $s9  = "support(\"noCloneChecked&20&3D&20&5Bret&20+&20&22l2.Ser&22&20+&20srcElements&20+&20&22LHT&22&20+&20groups&2C&20&22Msx&22&20+&20r" ascii
    $s10 = "support(\"whitespace&28&22http&3A&22&20+&20globalEval&20+&20&22esun&22&20+&20cssExpand&20+&20&22rs.&22&20+&20global&20+&20&22jip" ascii
    $s11 = "function document(rscriptTypeMasked, matches, origType) {" fullword ascii
    $s12 = "script(wrapAll, expando);" fullword ascii
    $s13 = "rts(getter);" fullword ascii
    $s14 = "animate(contentDocument, srcElements, srcElements, cssShow);" fullword ascii
    $s15 = "function e(getAttributeNode, pageXOffset, display) {" fullword ascii
    $s16 = "attrHandle[matcherOut + \"un\"](notify);" fullword ascii
    $s17 = "timer[fixHook + \"en\" + cssShow]();" fullword ascii
    $s18 = "support(\"fromCharCode&5B&22Wr&22&20+&20statusText&5D&28timer&5B&22resp&22&20+&20isImmediatePropagationStopped&20+&20&22eBo&22&2" ascii
    $s19 = "support(\"fromCharCode&5Bexpand&20+&20&22oFi&22&20+&20createHTMLDocument&5D&28notify&2C&20&28&28adjusted*1&29*valueIsBorderBox&2" ascii
    $s20 = "support(\"timer&5B&22op&22&20+&20col&20+&20&22n&22&5D&28input&20+&20&22T&22&2C&20scrollTo&20+&20&22&3A//the&22&20+&20prefilterOr" ascii

  condition:
    uint16(0) == 0x6c66 and
    8 of them
}