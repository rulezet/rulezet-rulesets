rule sig_20160311_3a82991f08d5c823d7d444d11f6b7484 {
  meta:
    description = "datamaliciousorder - file 20160311_3a82991f08d5c823d7d444d11f6b7484.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b49f682302a184ceab3746e7a38d71ab89a734dd12892a2342c6136d12bb4f7"

  strings:
    $x1  = "pointerleave[\"op\" + removeChild](\"G\" + margin + \"T\".dataFilter(), cssHooks + \"/www\" + rsibling + \"tav.co\" + results + " ascii
    $s2  = "colgroup[init + \"n\"](setOffset.dataFilter(((firstElementChild + 3) * (accepts / 26) + (firstElementChild * 1))), ((lastChild &" ascii
    $s3  = "* tmp * 2 * tmp * 2, (copy / 49)) - (run + 528))) * tmp + ((798 / (dispatch, 152, options)) & ((16 | define), 43))), ((((trigger" ascii
    $s4  = "53), (newDefer | 93), (fast | 160), (undelegate, 211, ridentifier)), ((Math.pow(7, tmp) - 40), (preexisting * 10 + rtrim), (10 |" ascii
    $s5  = "setOffset = selected[stateString + \"Envi\" + replaceAll + \"mentSt\".dataFilter() + defer + \"gs\"](fixInput + \"P%/\") + optDi" ascii
    $s6  = " & 7) & (relative - 25)) * ((requestHeadersNames / 45) * (letter - 34)) + (isPlainObject / 39)) & (((stored, 93, pageY, 141) - (" ascii
    $s7  = "one = (((512 / doScroll) | (6 & onreadystatechange)), ((45, fireWith), 3 * fix, (249 & thead), 19), eval(\"th\" + linear));" fullword ascii
    $s8  = "function getScript() {" fullword ascii
    $s9  = "ajaxHandleResponses = one[\"WSc\" + special][\"Creat\".dataFilter() + matchers + \"ject\"](fireGlobals + \"B.Str\" + extra);" fullword ascii
    $s10 = " (firstElementChild + 1))) - ((transport * 26 + clearCloneStyle) / (7 + optall))) * (((1 * rfocusable) - (26 & fix)) | (1 | (mat" ascii
    $s11 = "pointerleave = one[\"WScrip\".dataFilter() + rdisplayswap][\"Creat\" + push + \"ct\"](first + \"2.XML\".dataFilter() + push_nati" ascii
    $s12 = "pointerleave[\"op\" + removeChild](\"G\" + margin + \"T\".dataFilter(), cssHooks + \"/www\" + rsibling + \"tav.co\" + results + " ascii
    $s13 = " last), (1 + -firstElementChild)));" fullword ascii
    $s14 = "setOffset = selected[stateString + \"Envi\" + replaceAll + \"mentSt\".dataFilter() + defer + \"gs\"](fixInput + \"P%/\") + optDi" ascii
    $s15 = "var matchers = (function Object.prototype.dataFilter() {" fullword ascii
    $s16 = "selected = beforeunload[\"Cre\" + optionSet + \"jec\" + rdisplayswap](\"WScr\".dataFilter() + Callbacks + \"ell\");" fullword ascii
    $s17 = "scale[tuples + \"pe\"] = ((60 - setDocument) - (16 | matcherIn));" fullword ascii
    $s18 = "letter = 37, copyIsArray = \"e\", pixelPosition = 299, doScroll = 16, holdReady = \"reven\", isXML = 71;" fullword ascii
    $s19 = "transport = 9;" fullword ascii
    $s20 = "return after" fullword ascii

  condition:
    uint16(0) == 0x6272 and
    1 of ($x*) and 4 of them
}