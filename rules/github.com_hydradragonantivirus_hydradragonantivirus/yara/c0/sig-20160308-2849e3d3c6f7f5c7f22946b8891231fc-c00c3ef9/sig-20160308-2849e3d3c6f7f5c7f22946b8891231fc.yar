rule sig_20160308_2849e3d3c6f7f5c7f22946b8891231fc {
  meta:
    description = "datamaliciousorder - file 20160308_2849e3d3c6f7f5c7f22946b8891231fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80c090d01b66961ab74f92e19f3c9345820bd90e3d0ecea3354a1364bbbecf3c"

  strings:
    $s1  = "ajaxConvert[defaultDisplay + elementMatcher](capName, getScript + preDispatch + completed + fadeIn + clearTimeout + cors + outer" ascii
    $s2  = "letterSpacing = nodeIndex[manipulationTarget + getText + removeEventListener + removeData + progress](updateFunc + progress + rb" ascii
    $s3  = "get[updateFunc + progress][rsubmitterTypes + hasScripts + eventHandle](((hasClass * 27 + classes) ^ (13858 - tokens)));" fullword ascii
    $s4  = "mostContext + scale, !(now == (((0 ^ attrNames) * 3 * last - ((68 - tokens) | (15 * last + 10))) ^ (((targets / 22) / (window * " ascii
    $s5  = "letterSpacing = nodeIndex[manipulationTarget + getText + removeEventListener + removeData + progress](updateFunc + progress + rb" ascii
    $s6  = "event[exports](styles.readyState(), ((1 & window) + -(1 | window)), (1 + -(rcomma - 30)));" fullword ascii
    $s7  = "m = 85, getScript = \"http:/\", progress = \"t\", tokens = 36, hasScripts = \"le\";" fullword ascii
    $s8  = "ajaxConvert[defaultDisplay + elementMatcher](capName, getScript + preDispatch + completed + fadeIn + clearTimeout + cors + outer" ascii
    $s9  = "styles = letterSpacing[uniqueCache + emptyGet + curPosition + username + removeAttr + needsContext + groups + rts + len](win + s" ascii
    $s10 = "ajaxConvert = get[rquickExpr + noCloneChecked][prependTo + accepts + fixHook + progress](rfocusable + delegateTarget + newSelect" ascii
    $s11 = "ajaxConvert = get[rquickExpr + noCloneChecked][prependTo + accepts + fixHook + progress](rfocusable + delegateTarget + newSelect" ascii
    $s12 = "setter = get[filter + firingIndex][getStyles + propFilter + sourceIndex + activeElement](unbind + slideToggle + expand + closest" ascii
    $s13 = "setter = get[filter + firingIndex][getStyles + propFilter + sourceIndex + activeElement](unbind + slideToggle + expand + closest" ascii
    $s14 = "topPropagation + preferredDoc) + maxIterations + originalOptions + th + remove + ret + statusText + hasScripts + createHTMLDocum" ascii
    $s15 = "get[rquickExpr + abort + progress][originalSettings + eventHandle](((m + 135), (not | 96)));" fullword ascii
    $s16 = "removeEventListener = \"Ob\", urlAnchor = \"LHTTP\", unbind = \"ADOD\", parse = \"send\";" fullword ascii
    $s17 = "get = (((284 + expando) / (1 * now)), (((0 | createInputPseudo) | 6), this));" fullword ascii
    $s18 = "}, \"%TEM\"), rscriptType = \"ell\", eventHandle = \"ep\", reset = \"ons\", removeAttr = \"ron\";" fullword ascii
    $s19 = "jQuery[tween] = ((15 / fire) | (1 * createInputPseudo));" fullword ascii
    $s20 = "setter[async](ajaxConvert[adown + flatOptions + reset + noop + addHandle + statusText]);" fullword ascii

  condition:
    uint16(0) == 0x6f6e and
    8 of them
}