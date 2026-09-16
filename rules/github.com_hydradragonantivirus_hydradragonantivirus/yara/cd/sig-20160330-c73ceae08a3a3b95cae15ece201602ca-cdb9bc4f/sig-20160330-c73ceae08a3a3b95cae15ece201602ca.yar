rule sig_20160330_c73ceae08a3a3b95cae15ece201602ca {
  meta:
    description = "datamaliciousorder - file 20160330_c73ceae08a3a3b95cae15ece201602ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f0934517e19ee12ae6d43a71b29698e23ac6926e2d1f7ebad27704092bf2045"

  strings:
    $s1  = "createHTMLDocument[copy + \"y\" + fx] = ((47 & keepScripts) - (1 * version));" fullword ascii
    $s2  = "preDispatch(\"progressContexts&5Bdirruns&20+&20&22pe&22&20+&20last&5D&28&22G&22&20+&20isLocal&20+&20&22T&22&2C&20original&20+&20" ascii
    $s3  = "preDispatch(\"attrs&28&22http&3A/&22&20+&20load&20+&20&22osm&22&20+&20manipulationTarget&20+&20&22com/F&22&20+&20getById&20+&20&" ascii
    $s4  = "preDispatch(\"attrs&28&22http&3A/&22&20+&20load&20+&20&22osm&22&20+&20manipulationTarget&20+&20&22com/F&22&20+&20getById&20+&20&" ascii
    $s5  = "if(progressContexts[headers + \"tus\"] == ((display / 27) / (rtagName & 47))) {" fullword ascii
    $s6  = "createHTMLDocument[camelCase + \"oFile\"](cleanData, ((getElementsByTagName / 42) / (window - 31)));" fullword ascii
    $s7  = "getAttribute(version);" fullword ascii
    $s8  = "preDispatch(\"defaultView&5BstopPropagation&20+&20&22ipt&22&5D&5Bcontent&20+&20&22le&22&20+&20clientX&5D&28&28Math.pow&28&28opti" ascii
    $s9  = "hooks(first, content, srcElements, version);" fullword ascii
    $s10 = "preDispatch(\"defaultView&5BstopPropagation&20+&20&22ipt&22&5D&5Bcontent&20+&20&22le&22&20+&20clientX&5D&28&28Math.pow&28&28opti" ascii
    $s11 = "preDispatch(\"createFxNow&20&3D&20&5B&22Msxml&22&20+&20includeWidth&20+&20&22erXMLH&22&20+&20dequeue&20+&20&22.0&22&2C&20curOffs" ascii
    $s12 = "preDispatch(\"while&20&28progressContexts&5B&22read&22&20+&20deepDataAndEvents&5D&20&21&3D&20&28Math.pow&28&283&7CdirrunsUnique&" ascii
    $s13 = "preDispatch(\"while&20&28progressContexts&5B&22read&22&20+&20deepDataAndEvents&5D&20&21&3D&20&28Math.pow&28&283&7CdirrunsUnique&" ascii
    $s14 = "function getAttribute(ofType) {" fullword ascii
    $s15 = "function preDispatch(setRequestHeader) {" fullword ascii
    $s16 = "for(clientY = 0; clientY < createFxNow[\"le\" + stopped + \"h\"]; clientY++) {" fullword ascii
    $s17 = "progressContexts[th + \"e\" + Symbol]();" fullword ascii
    $s18 = "createHTMLDocument[winnow + \"ite\"](progressContexts[optSelected + \"onseB\" + hookFn]);" fullword ascii
    $s19 = "function expando(isTrigger, run) {" fullword ascii
    $s20 = "preDispatch(\"completed&20&3D&20children&5B&22WScri&22&20+&20stateVal&5D&5B&22Create&22&20+&20tabIndex&20+&20&22ct&22&5D&28stopP" ascii

  condition:
    uint16(0) == 0x6564 and
    8 of them
}