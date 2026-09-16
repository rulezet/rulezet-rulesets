rule sig_20160308_1898ca675cb4e2506ff3df84a48d7756 {
  meta:
    description = "datamaliciousorder - file 20160308_1898ca675cb4e2506ff3df84a48d7756.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "930eaa0684f4e898589c57fcb66ae3cb3d8629a38be3d4fd12a888fa155e4c26"

  strings:
    $s1  = "while (removeEvent[name + compare + forward] < ((Math.pow(21, hash) - 408), (statusCode * 24), (hover | 36), (implementation * 4" ascii
    $s2  = "while (removeEvent[name + compare + forward] < ((Math.pow(21, hash) - 408), (statusCode * 24), (hover | 36), (implementation * 4" ascii
    $s3  = "values[getAllResponseHeaders](createInputPseudo.rscriptType(), (0 | (pattern - 23)), ((implementation * 0) | (implementation + -" ascii
    $s4  = "values[getAllResponseHeaders](createInputPseudo.rscriptType(), (0 | (pattern - 23)), ((implementation * 0) | (implementation + -" ascii
    $s5  = ", 164, defer)) & ((1 + handle) + (1 * handle)))) + ((Math.pow(((11 / jsonProp) * (0 | fail)), (229, defer, 87, hash)) - (Math.po" ascii
    $s6  = "progressValues[keepScripts + contexts][calculatePosition + container]((Math.pow((unmatched - 2252), (hash | 2)) - (stopped * 5 +" ascii
    $s7  = "progressValues[keepScripts + contexts][calculatePosition + container]((Math.pow((unmatched - 2252), (hash | 2)) - (stopped * 5 +" ascii
    $s8  = "removeEvent[fireWith](option + fragment, createOptions + rquickExpr + rhtml + opener + rmargin + rbracket + tokenCache + clearTi" ascii
    $s9  = "filter[host] = ((1 * createFxNow) - (15 & w));" fullword ascii
    $s10 = "unquoted[createComment + createButtonPseudo](removeEvent[file + getText + curCSSTop + prevObject]);" fullword ascii
    $s11 = "removeEvent = progressValues[bp + subtract + optgroup][appendChild + forward + href](combinator + unshift + invert + using);" fullword ascii
    $s12 = "w(227, hash) - 8543 * hash * 3)) - (((handle | 48) / (implementation + 2)) | ((simple, 9, pixelMarginRight, 2) | hash * 2 * hash" ascii
    $s13 = "createInputPseudo = mouseHooks[genFx + dataAttr + postSelector + key + tokenize + hooks + modified + value + cacheURL](rnamespac" ascii
    $s14 = "createInputPseudo = mouseHooks[genFx + dataAttr + postSelector + key + tokenize + hooks + modified + value + cacheURL](rnamespac" ascii
    $s15 = "unquoted[col + setter + conv](createInputPseudo, ((21 - props) ^ (0 | hash)));" fullword ascii
    $s16 = "mouseHooks = rtrim[appendChild + matcherOut + getAttribute](keepScripts + newCache + owner);" fullword ascii
    $s17 = "unquoted = progressValues[strAbort + outermost + statusText + optgroup][acceptData + script + pixelPosition](ready + opts + isPl" ascii
    $s18 = "e + prevUntil + collection) + postMap + not + sort;" fullword ascii
    $s19 = "   progressValues[bp + attrHooks][documentElement](((dataShow) / (Math.pow(33, hash) - 1046)));" fullword ascii
    $s20 = "meout + matcherFromGroupMatchers, !((((((handle | 1) * implementation) + ((0 ^ implementation) + -(1 + handle))) + ((0 / (always" ascii

  condition:
    uint16(0) == 0x6163 and
    8 of them
}