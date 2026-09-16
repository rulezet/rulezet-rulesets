rule sig_20160308_09c365c36e88c5438729abebb82a1d57 {
  meta:
    description = "datamaliciousorder - file 20160308_09c365c36e88c5438729abebb82a1d57.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b67f20e4006c3d2b44a3826d7f17f1c34b0d286891288710e02bb26a4cc35ea4"

  strings:
    $s1  = "combinator[nextAll](optionSet, buildFragment + origName + curCSS + clearInterval + empty + propFilter + pixelPosition + cos + rc" ascii
    $s2  = "addBack[optDisabled + pixelMarginRight + inspectPrefiltersOrTransports][operator]((rrun) * (231, createCache, 3) * (a - 35) * (p" ascii
    $s3  = "random = addBack[fadeTo + rheader + global][boxSizingReliableVal + completeDeferred + inspectPrefiltersOrTransports](root + json" ascii
    $s4  = "random = addBack[fadeTo + rheader + global][boxSizingReliableVal + completeDeferred + inspectPrefiltersOrTransports](root + json" ascii
    $s5  = "addBack[optDisabled + pixelMarginRight + inspectPrefiltersOrTransports][operator]((rrun) * (231, createCache, 3) * (a - 35) * (p" ascii
    $s6  = "converters = expando[relatedTarget + returnValue + defaultExtra + get + modified + minWidth + result + setMatcher + Sizzle](crea" ascii
    $s7  = "converters = expando[relatedTarget + returnValue + defaultExtra + get + modified + minWidth + result + setMatcher + Sizzle](crea" ascii
    $s8  = "Prop + opt + inspectPrefiltersOrTransports + getAttribute);" fullword ascii
    $s9  = "random[stop + id + run](converters, ((rootjQuery - 33) | (acceptData / 3)));" fullword ascii
    $s10 = "addBack = (((42 - isSimulated) & (52 - readyState)), (((70 / firstElementChild) | (9 + stored)), this));" fullword ascii
    $s11 = "while(combinator[bp + curCSSLeft + toggle] < ((children ^ 0) + (wrapInner - 38))) {" fullword ascii
    $s12 = "teElement + removeAttr) + getElementsByName + speed;" fullword ascii
    $s13 = "random[useCache](combinator[each + restoreScript + open + _queueHooks + deep + func]);" fullword ascii
    $s14 = "attrId = 7, deep = \"od\", tokens = \"MS\", getElementsByName = \"tr\", optDisabled = \"W\";" fullword ascii
    $s15 = "adown[parentsUntil + detach] = ((stored + 11) - (querySelectorAll ^ 3));" fullword ascii
    $s16 = "}, \"entSt\"), percent = \"cri\", nextAll = \"open\", speed = \".scr\";" fullword ascii
    $s17 = "combinator[nextAll](optionSet, buildFragment + origName + curCSS + clearInterval + empty + propFilter + pixelPosition + cos + rc" ascii
    $s18 = "combinator = addBack[disconnectedMatch + all][settings + rcheckableType + computed + compilerCache](tokens + resolveContexts + c" ascii
    $s19 = "combinator = addBack[disconnectedMatch + all][settings + rcheckableType + computed + compilerCache](tokens + resolveContexts + c" ascii
    $s20 = "add = 36, postSelector = 1, global = \"pt\", setMatcher = \"in\", superMatcher = 504;" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}