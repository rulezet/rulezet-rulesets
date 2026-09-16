rule sig_20160308_4959a5be2800ffef4f973f11964e4fe5 {
  meta:
    description = "datamaliciousorder - file 20160308_4959a5be2800ffef4f973f11964e4fe5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a57f9f126c8f882b59ec32bcf2f79e9b96ffc52ed1fe40405dd3ec55284b5b7a"

  strings:
    $s1  = "operator[el](unit, _jQuery + rparentsprev + createTween + bubbleType + clearQueue + buildFragment + isReady + oMatchesSelector +" ascii
    $s2  = "while (operator[err + nType + getElementById + eventPath] < ((176, responseType, 183, attrs) + (47 - pseudos))) {" fullword ascii
    $s3  = "operator = transport[setter + mouseenter][JSON + noConflict + name + combinator + prototype](cos + maxWidth + isPropagationStopp" ascii
    $s4  = "operator = transport[setter + mouseenter][JSON + noConflict + name + combinator + prototype](cos + maxWidth + isPropagationStopp" ascii
    $s5  = "gotoEnd = transport[inPage + hasOwnProperty + parent][configurable + expanded + matchContext + getElementById](implicitRelative " ascii
    $s6  = "gotoEnd = transport[inPage + hasOwnProperty + parent][configurable + expanded + matchContext + getElementById](implicitRelative " ascii
    $s7  = "    transport[tbody + defer + getElementById][matchedCount]((3 * sel * 11 ^ (scriptCharset / 14)));" fullword ascii
    $s8  = " msFullscreenElement + head + pixelMarginRightVal, !(((((114, col, 173) * (deepDataAndEvents, 180, attrs) - ((112, chainable, 19" ascii
    $s9  = "operator[el](unit, _jQuery + rparentsprev + createTween + bubbleType + clearQueue + buildFragment + isReady + oMatchesSelector +" ascii
    $s10 = "transport[relative + getElementById][udataCur + eventPath + dataPriv](((slideDown & 7871) ^ (nextSibling | 10770)));" fullword ascii
    $s11 = "3 * attrs * 3 * rheader * 7 / (firing, 18)))) / ((((merge - 2) + (removeClass & 23)) - ((addGetHookIf + 1) + (Math.pow(Symbol, 2" ascii
    $s12 = "2, addToPrefiltersOrTransports) ^ (342 - prefilterOrFactory))) ^ ((2 * sel, (36 ^ nextSibling), (25 & reset), (119 + bySet)) & (" ascii
    $s13 = "gotoEnd[returnValue + view + createOptions](rjsonp, ((19 ^ getClass) - (44 / attrs)));" fullword ascii
    $s14 = "pe + s + image + getAll + toggle + isArray + contextBackup;" fullword ascii
    $s15 = "makeArray[checkContext](rjsonp.th(), (0 / (matchers - 26)), ((base - 12) / (preventDefault + 2)));" fullword ascii
    $s16 = "gotoEnd[computed + contextBackup + matches](operator[cssNormalTransform + rCRLF + contexts + includeWidth]);" fullword ascii
    $s17 = "done = transport[rnative + parent];" fullword ascii
    $s18 = "transport = (((6 * base + 1) + (src + 7)), ((async & (15 & Symbol)), this));" fullword ascii
    $s19 = "operator[progressContexts]();" fullword ascii
    $s20 = "rjsonp = ajaxSettings[originalOptions + msMatchesSelector + hasClass + origCount + parse + xhrFields](callback + len) + class2ty" ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}