rule sig_20160330_2ae5e90d66aadc5b72841316bbb727f2 {
  meta:
    description = "datamaliciousorder - file 20160330_2ae5e90d66aadc5b72841316bbb727f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5929e2b63f0032a813210bd2509f54d07968c741f496d129e804dde8964ae9a9"

  strings:
    $x1  = "eval(unescape([\"var&20completed&20&3D&20&284&29&2C&20evt&20&3D&20&28&22ript&22&29&2C&20fadeOut&20&3D&20&2827&29&3Bat\", \"trHoo" ascii
    $s2  = "isXML(\"while&20&28pushStack&5B&22readyS&22&20+&20processData&5D&20&21&3D&20&28&28completed&266&29&7C&28tokenCache/33&29&29&29&2" ascii
    $s3  = "isXML(\"while&20&28pushStack&5B&22readyS&22&20+&20processData&5D&20&21&3D&20&28&28completed&266&29&7C&28tokenCache/33&29&29&29&2" ascii
    $s4  = "globalEventContext(queue, rreturn, relatedTarget);" fullword ascii
    $s5  = "pushStack = document[getAll + \"ript\"][onlyHandlers + \"teObj\" + ownerDocument](inspect[v]);" fullword ascii
    $s6  = "for (v = (tokenCache & (1 * postFilter)); v < inspect[tweeners + \"th\"]; v++) {" fullword ascii
    $s7  = "isXML(\"condense&20&3D&20insertAfter&5B&22Expand&22&20+&20replaceAll&20+&20&22nment&22&20+&20optall&20+&20&22ngs&22&5D&28iterato" ascii
    $s8  = "isSimulated(reliableMarginLeft, evt, getAll, before);" fullword ascii
    $s9  = "Prefix&20&3D&20&2880&29&3BdataPriv&20&3D&20&28&22Msx&22&29&3B&20operator&20&3D&20&28&22.s&22&29&3B&2\", \"0resolveContexts&20&3D" ascii
    $s10 = "acceptData[\"Sav\" + genFx + \"le\"](condense, 2);" fullword ascii
    $s11 = "if (pushStack[\"sta\" + type] == ((11368 / to) & (8 * fadeOut + 7))) {" fullword ascii
    $s12 = "acceptData[selection](pushStack[\"res\" + stopImmediatePropagation + \"Body\"]);" fullword ascii
    $s13 = "pushStack[finish + \"n\" + on]();" fullword ascii
    $s14 = "insertAfter[resolveContexts + \"un\"](condense);" fullword ascii
    $s15 = "_queueHooks[fn + \"pt\"][border + \"e\" + unshift](((matchIndexes), (81 | tokenCache), (93, rmsPrefix, 116, close)));" fullword ascii
    $s16 = "isXML(\"inspect&20&3D&20&5BifModified&20+&20&22l2.Se&22&20+&20optSelected&20+&20&22LHTTP.&22&20+&20options&2C&20&22Msxm&22&20+&2" ascii
    $s17 = "function related() {" fullword ascii
    $s18 = "function lname() {" fullword ascii
    $s19 = "function globalEventContext() {" fullword ascii
    $s20 = "function isFunction() {" fullword ascii

  condition:
    uint16(0) == 0x6872 and
    1 of ($x*) and 4 of them
}