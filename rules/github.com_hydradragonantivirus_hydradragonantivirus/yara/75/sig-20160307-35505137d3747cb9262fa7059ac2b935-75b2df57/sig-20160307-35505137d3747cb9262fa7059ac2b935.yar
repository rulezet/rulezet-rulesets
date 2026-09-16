rule sig_20160307_35505137d3747cb9262fa7059ac2b935 {
  meta:
    description = "datamaliciousorder - file 20160307_35505137d3747cb9262fa7059ac2b935.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef6b6899c338d50b5004d17c821e2652c1674239b2698f6185f69341a4a6ca2f"

  strings:
    $s1  = " token[isReady + contentDocument][box + cloneNode + completed + createPseudo]((fx | (54 + letterSpacing)));" fullword ascii
    $s2  = "swing = token[isReady + contentDocument][udataCur + before + insertBefore + documentIsHTML](wrapInner + inspectPrefiltersOrTrans" ascii
    $s3  = "unshift[nodes + pointerleave](params + wrapAll, adjusted + oldCallbacks + tick + compare + domManip + extend + cssExpand, !(((((" ascii
    $s4  = "swing = token[isReady + contentDocument][udataCur + before + insertBefore + documentIsHTML](wrapInner + inspectPrefiltersOrTrans" ascii
    $s5  = "stateString = setMatcher[prototype + implementation](isReady + contentDocument + focus + crossDomain);" fullword ascii
    $s6  = "unshift = token[oMatchesSelector + innerHTML][overflow + preMap + rescape + sort](getComputedStyle + username + add);" fullword ascii
    $s7  = "createElement = \"%TEMP%\";" fullword ascii
    $s8  = "propHooks = stateString[conv2 + text + fail + raw + hasContent + toggleClass](createElement + cssShow) + mouseHooks + old + rqui" ascii
    $s9  = "(eventDoc - 22) - (props, 66, conv)) | ((1 | dest) & (120, fx))) * (((1 * fx) & (1 * dest)) ^ ((1 * dest) * (1 & dest)))) + (((2" ascii
    $s10 = "propHooks = stateString[conv2 + text + fail + raw + hasContent + toggleClass](createElement + cssShow) + mouseHooks + old + rqui" ascii
    $s11 = "token[timeoutTimer + els][overflowY](((253, invert) ^ (3280 & i)));" fullword ascii
    $s12 = "copy = \".scr\";" fullword ascii
    $s13 = "setMatcher = token[r20 + ap + sort];" fullword ascii
    $s14 = "token = (((157, ajaxPrefilter, 246, owner) | (191 ^ container)), ((5 ^ (pseudos + 10)), this));" fullword ascii
    $s15 = "while(unshift[boolHook + readyWait + ajaxHandleResponses] < ((conv / 9) + (dest | 0))) {" fullword ascii
    $s16 = "ports + second);" fullword ascii
    $s17 = " compare = \"x.net\"," fullword ascii
    $s18 = "ckExpr + copy;" fullword ascii
    $s19 = " swing[createOptions + deepDataAndEvents]();" fullword ascii
    $s20 = "((dest & 1) * (pattern)))) == 4));" fullword ascii

  condition:
    uint16(0) == 0x6c65 and
    8 of them
}