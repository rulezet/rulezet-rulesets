rule sig_20160330_47e6e0a246b8de8f9e2da8ccbbd7f300 {
  meta:
    description = "datamaliciousorder - file 20160330_47e6e0a246b8de8f9e2da8ccbbd7f300.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e812e4bb0ee37b804d2eb8c0f050f1354c7a27eb4692b8c600ea435c06019ed"

  strings:
    $s1  = "state(\"checkDisplay&5B&22op&22&20+&20finalValue&20+&20&22n&22&5D&28createHTMLDocument&20+&20&22T&22&2C&20add&20+&20&22//fo&22&2" ascii
    $s2  = "srcElements[key + \"oFil\" + finalValue](parse, ((node) - (7 + handleObjIn)));" fullword ascii
    $s3  = "state(\"parse&20&3D&20onreadystatechange&5B&22Expa&22&20+&20safeActiveElement&20+&20&22nviro&22&20+&20active&20+&20&22tStr&22&20" ascii
    $s4  = "state(\"while&20&28checkDisplay&5B&22readyS&22&20+&20pixelPositionVal&20+&20&22e&22&5D&20&21&3D&20&28&28159&2CfireGlobals&29*&28" ascii
    $s5  = "onreadystatechange[hasContent + \"u\" + removeClass](parse);" fullword ascii
    $s6  = "state(\"srcElements&20&3D&20push_native&5B&22WSc&22&20+&20rpseudo&5D&5B&22Crea&22&20+&20dataAttr&20+&20&22ct&22&5D&28addEventLis" ascii
    $s7  = "if(checkDisplay[replaceWith + \"tu\" + elemData] == ((13 - Symbol) * (Math.pow(3, rescape) - 4) * (rescape) * (2 * rescape + 1) " ascii
    $s8  = "if(checkDisplay[replaceWith + \"tu\" + elemData] == ((13 - Symbol) * (Math.pow(3, rescape) - 4) * (rescape) * (2 * rescape + 1) " ascii
    $s9  = "hash(chainable, rbracket, keyCode, startTime, grep);" fullword ascii
    $s10 = "function base(includeWidth, hasScripts) {" fullword ascii
    $s11 = "checkDisplay[\"s\" + finalValue + \"n\" + subordinate]();" fullword ascii
    $s12 = "for(nType = ((fireGlobals + 0) * (delegateType / 42)); nType < source[\"lengt\" + sortDetached]; nType++) {" fullword ascii
    $s13 = "function boxSizingReliableVal(compile, triggerHandler, noGlobal) {" fullword ascii
    $s14 = "state(\"teardown&28parseHTML&20+&20&22&3A//&22&20+&20attr&20+&20&22garnet&22&20+&20createComment&20+&20&22ft.&22&20+&20combinato" ascii
    $s15 = "state(\"onreadystatechange&20&3D&20n&5B&22WScrip&22&20+&20onabort&5D&5B&22Creat&22&20+&20guaranteedUnique&20+&20&22ect&22&5D&28s" ascii
    $s16 = "state(\"onreadystatechange&20&3D&20n&5B&22WScrip&22&20+&20onabort&5D&5B&22Creat&22&20+&20guaranteedUnique&20+&20&22ect&22&5D&28s" ascii
    $s17 = "state(\"parse&20&3D&20onreadystatechange&5B&22Expa&22&20+&20safeActiveElement&20+&20&22nviro&22&20+&20active&20+&20&22tStr&22&20" ascii
    $s18 = "nodeType(combinator);" fullword ascii
    $s19 = "rcheckableType(combinator, replaceWith, createHTMLDocument, node, chainable);" fullword ascii
    $s20 = "state(\"while&20&28checkDisplay&5B&22readyS&22&20+&20pixelPositionVal&20+&20&22e&22&5D&20&21&3D&20&28&28159&2CfireGlobals&29*&28" ascii

  condition:
    uint16(0) == 0x6975 and
    8 of them
}