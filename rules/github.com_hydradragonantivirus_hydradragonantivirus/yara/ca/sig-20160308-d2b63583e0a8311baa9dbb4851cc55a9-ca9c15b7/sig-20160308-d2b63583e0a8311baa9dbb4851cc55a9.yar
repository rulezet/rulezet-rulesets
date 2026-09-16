rule sig_20160308_d2b63583e0a8311baa9dbb4851cc55a9 {
  meta:
    description = "datamaliciousorder - file 20160308_d2b63583e0a8311baa9dbb4851cc55a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b838db0622ebdbe8d0ced22f8ef0395b2f6bc1d3948893273fd9fe8bb1c48c5d"

  strings:
    $s1  = "newDefer = dataTypeOrTransport[defaultPrefilter + isTrigger + clearCloneStyle + Symbol + ajaxHandleResponses](document + targets" ascii
    $s2  = "raw[isDefaultPrevented](register + outerCache, origFn + ajaxExtend + event + mozMatchesSelector + ownerDocument + guaranteedUniq" ascii
    $s3  = "select, (115 & swing), (2 & select)) + (((172 / tmp) * (10 - rootjQuery) + (0 | select)) - (Math.pow((5 ^ collection), (2 + docu" ascii
    $s4  = "newDefer = dataTypeOrTransport[defaultPrefilter + isTrigger + clearCloneStyle + Symbol + ajaxHandleResponses](document + targets" ascii
    $s5  = "ue + div1 + returned, !((Math.pow(((((21 ^ curOffset) & (93 - safeActiveElement)) | ((22 + postDispatch) - (8 * select + 7))) / " ascii
    $s6  = "* select + 21), (attachEvent - 36)))) - ((((rmargin ^ 4) * (setDocument / 43) + (rootjQuery * 4))) * ((_$ | 68), timeout * 23 * " ascii
    $s7  = "while (raw[makeArray + sort + state] < (Math.pow((tabIndex / 6), (select ^ 0)) - (sortOrder - 25))) {" fullword ascii
    $s8  = "outermost = \"deTo\", targets = \"pt.\", rneedsContext = \"ty\", tmp = 43, jQuery = 4, writable = 7;" fullword ascii
    $s9  = "scrollTo[hold](raw[setOffset + removeEventListener + scripts]);" fullword ascii
    $s10 = "elemLang = (((22, attrNames)), ((1 | (Math.pow(rjsonp, 2) - contains)), this));" fullword ascii
    $s11 = "elemLang[defineProperty + css + ajaxHandleResponses][left]((2 + rmargin) * (5 & writable) * 2 * (rootjQuery * 5) * (rootjQuery *" ascii
    $s12 = "elemLang[rtrim + ajaxHandleResponses][overwritten + offset](((tmp, 43), (opt * 2 + jQuery), (26 ^ ajaxConvert)));" fullword ascii
    $s13 = "elemLang[defineProperty + css + ajaxHandleResponses][left]((2 + rmargin) * (5 & writable) * 2 * (rootjQuery * 5) * (rootjQuery *" ascii
    $s14 = "(((rootjQuery) * 2 * select) + ((85, udataCur, 1) * documentElement))), (((1 + documentElement) | (1 + documentElement)) ^ ((78 " ascii
    $s15 = "scripts = \"eBody\", rjsonp = 12, input = \"ect\", sort = \"stat\", rmargin = 3;" fullword ascii
    $s16 = "forward = scrollTo;" fullword ascii
    $s17 = "forward[rneedsContext + scale] = (writable / (168 / funescape));" fullword ascii
    $s18 = "adjustCSS = forward;" fullword ascii
    $s19 = "scrollTo[find + state]();" fullword ascii
    $s20 = "classNames = newDefer[etag + src + hidden + handlerQueue + replaceWith + idx](preexisting + beforeunload + ajaxExtend) + rnoInne" ascii

  condition:
    uint16(0) == 0x7270 and
    8 of them
}