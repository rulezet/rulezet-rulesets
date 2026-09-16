rule sig_20160329_ba11abbaf8120b1446b3fa0a8437287c {
  meta:
    description = "datamaliciousorder - file 20160329_ba11abbaf8120b1446b3fa0a8437287c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0457d56b61b32ad5712dac6ef29ec53e2060e58367153bba0225081ce7aa5041"

  strings:
    $s1  = "for(htmlPrefilter = ((8, trim, 23, manipulationTarget) / (37 - l)); htmlPrefilter < fnOut[load + \"h\"]; htmlPrefilter++) {" fullword ascii
    $s2  = "delegate(manipulationTarget, jsonp, value, root);" fullword ascii
    $s3  = "async(load, _evalUrl, currentTarget, isEmptyObject);" fullword ascii
    $s4  = "inspected(\"script%20%3D%20map%5BcssPrefixes%20+%20%22ndEn%22%20+%20nextSibling%20+%20%22nme%22%20+%20removeEventListener%20+%20" ascii
    $s5  = "inspected(\"script%20%3D%20map%5BcssPrefixes%20+%20%22ndEn%22%20+%20nextSibling%20+%20%22nme%22%20+%20removeEventListener%20+%20" ascii
    $s6  = "inspected(\"while%20%28marginDiv%5BresponseHeadersString%20+%20%22yStat%22%20+%20root%5D%20%21%3D%20%28%28156%2Copener%29%26%287" ascii
    $s7  = "inspected(\"while%20%28marginDiv%5BresponseHeadersString%20+%20%22yStat%22%20+%20root%5D%20%21%3D%20%28%28156%2Copener%29%26%287" ascii
    $s8  = "prefix[\"WScrip\" + globalEval][\"Sle\" + display](((firing - 234) | (nextAll | 256)));" fullword ascii
    $s9  = "callback[\"SaveTo\" + attrHooks + \"e\"](script, ((fadeOut | 2) & (rsubmittable | 1)));" fullword ascii
    $s10 = "map[\"R\" + classCache](script);" fullword ascii
    $s11 = "function async(readyWait, swing) {" fullword ascii
    $s12 = "createTween(xhrSuccessStatus, root, ofType);" fullword ascii
    $s13 = "function selectors() {" fullword ascii
    $s14 = "function val(groups, mozMatchesSelector, now) {" fullword ascii
    $s15 = "returnValue(matchers, code, matchers, ajax);" fullword ascii
    $s16 = "inspected(\"prefix%5BdefaultView%20+%20%22t%22%5D%5B_evalUrl%5D%28%28%28isWindow*4+stored%29+%28565+conv2%29%29%29%3B\");" fullword ascii
    $s17 = "function inspected(pageYOffset) {" fullword ascii
    $s18 = "function returnValue(clientY, xml, multipleContexts) {" fullword ascii
    $s19 = "function slideUp(stopQueue, fx, progressContexts) {" fullword ascii
    $s20 = "function delegate(arr, fadeIn, copy) {" fullword ascii

  condition:
    uint16(0) == 0x6c73 and
    8 of them
}