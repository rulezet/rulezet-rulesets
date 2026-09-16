rule sig_20160307_1ccd6b96ad45bfcd743590931c7fc913 {
  meta:
    description = "datamaliciousorder - file 20160307_1ccd6b96ad45bfcd743590931c7fc913.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1bcdb1406b38fb39c80859af4905904d22a4085a8ba7e9f68613cc3388cde64"

  strings:
    $s1  = "dir[_data + invert][addGetHookIf]((5 & lname) * (10 - rcleanScript) * 2 * (nid ^ 0) * (reject & 3) * (setMatchers | 1) * (setMat" ascii
    $s2  = "dir[_data + invert][addGetHookIf]((5 & lname) * (10 - rcleanScript) * 2 * (nid ^ 0) * (reject & 3) * (setMatchers | 1) * (setMat" ascii
    $s3  = "animated = opt[addCombinator + ajaxConvert + defaultPrefilter + invert](keepScripts + visibility + getElementsByName + cors);" fullword ascii
    $s4  = "tfoot[pageY](finalValue + postDispatch, len + progressContexts + handler + extend + newContext + readyState + rchecked + seed, !" ascii
    $s5  = "(8 < (((((addHandle * 2 + response) - 13) - ((activeElement, 86, specified, 214), (Math.pow(transport, 2) - prevUntil))) & (((89" ascii
    $s6  = "tfoot = dir[postFilter + window + refElements][addCombinator + onload + isArray + isPlainObject](elementMatcher + checkContext +" ascii
    $s7  = "tfoot = dir[postFilter + window + refElements][addCombinator + onload + isArray + isPlainObject](elementMatcher + checkContext +" ascii
    $s8  = "tfoot[pageY](finalValue + postDispatch, len + progressContexts + handler + extend + newContext + readyState + rchecked + seed, !" ascii
    $s9  = "dir[_data + invert][prevObject + copyIsArray]((Math.pow(19 * lname, (46 - createInputPseudo)) - (14472 - emptyStyle)));" fullword ascii
    $s10 = "3 + (tweener / 45))) * (on - (3 * lname * 3 * reject * 2 * reject / 2 * nid * 2 * reject)) + ((Math.pow((15 & notify), (1 ^ nid)" ascii
    $s11 = "ector + temp + checkClone;" fullword ascii
    $s12 = ") - (176 & nodeName)) / ((Math.pow(377, reject) - 141729) / (Math.pow(mouseleave, 2) - rsibling)))))));" fullword ascii
    $s13 = "dir = (((108 + lname) + (22 - notify)), (((4 | showHide) & (9 | rcombinators)), this));" fullword ascii
    $s14 = "while(tfoot[opacity + getClientRects + eventHandle + elem] < ((2 * reject) & (1 | count))) {" fullword ascii
    $s15 = "prop = dir[postFilter + toSelector][Deferred + suffix + values + nonce](pdataCur + event + open + tr);" fullword ascii
    $s16 = "rtypenamespace[postSelector + flatOptions] = ((insertAfter & 1) | (getText, 28, toggle, 1));" fullword ascii
    $s17 = "prop[rmargin + dataTypeExpression + jQuery](firstElementChild, ((insertAfter + -1) ^ (notify - 12)));" fullword ascii
    $s18 = "temp = \"ne\"," fullword ascii
    $s19 = "firstElementChild = animated[insertBefore + rescape + matcherIn + open + dataType](speeds + removeEvent) + _jQuery + nodeNameSel" ascii
    $s20 = "prop[tick + dataShow]();" fullword ascii

  condition:
    uint16(0) == 0x516a and
    8 of them
}