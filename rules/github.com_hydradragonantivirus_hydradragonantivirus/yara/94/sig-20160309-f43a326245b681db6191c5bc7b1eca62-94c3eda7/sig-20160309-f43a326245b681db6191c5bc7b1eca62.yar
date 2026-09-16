rule sig_20160309_f43a326245b681db6191c5bc7b1eca62 {
  meta:
    description = "datamaliciousorder - file 20160309_f43a326245b681db6191c5bc7b1eca62.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1fae10422b0c218d15073914cad36386e4a40d0a220f6b29e4fdcdcd6735aca"

  strings:
    $s1  = "bup[offsetWidth + notifyWith](matcherFromTokens + responses, resolveWith + docElem + mozMatchesSelector + nativeStatusText + isT" ascii
    $s2  = "parents[abort + isTrigger + docElem][detach + Data](((Math.pow(3845, computed) - 14780158) + (stop / 44)));" fullword ascii
    $s3  = "parents = (((438 / curCSS) - (Math.pow(20, computed) - 365)), ((rinputs, 181, dataFilter, 2) * (write | 2), this));" fullword ascii
    $s4  = ".pow((102 - grep), (0 | computed)) - (3181 + eventHandle)) - (7 & expanded) * (Math.pow(6, computed) - 29))) & (Math.pow(genFx, " ascii
    $s5  = "eDispatch, !(src < (((((18 ^ seekingTransport) * (0 | computed) + (13 | elems)) - ((949 ^ globalEval) / 7 * nodeValue)) - ((Math" ascii
    $s6  = "getWindow = parents[fail + matchExpr];" fullword ascii
    $s7  = "rigger + replaceAll + implementation + finalDataType + onerror + tmp + load + isImmediatePropagationStopped + url + initial + pr" ascii
    $s8  = "divStyle = getWindow[nodeNameSelector + risSimple + prepend + excess + docElem](abort + onlyHandlers + sortDetached);" fullword ascii
    $s9  = "requestHeaders[excess + wrapMap]();" fullword ascii
    $s10 = "resolveContexts[progress + setDocument + onload](rneedsContext, ((open + 18) - (implicitRelative * 2 + speeds)));" fullword ascii
    $s11 = "bup = parents[fail + nodeType + isTrigger + docElem][simple + Expr + duration](method + animate + charCode + nodes);" fullword ascii
    $s12 = "createOptions[origType](rneedsContext.sortOrder(), (write / 25), (write / 3 * computed * 3));" fullword ascii
    $s13 = "rneedsContext = divStyle[num + t + closest + keyCode + nid + writable](createDocumentFragment + marginDiv) + isWindow + matcherO" ascii
    $s14 = "rneedsContext = divStyle[num + t + closest + keyCode + nid + writable](createDocumentFragment + marginDiv) + isWindow + matcherO" ascii
    $s15 = "resolveContexts = parents[_jQuery + isPlainObject][simple + interval + cssExpand + next + docElem](bp + xhr + attributes);" fullword ascii
    $s16 = "nodeType = \"ri\", mouseleave = \".sc\", keyCode = \"ntS\", animate = \"XML2.\", prepend = \"Obje\", matcherOut = \"GATIV\";" fullword ascii
    $s17 = "simple = \"Cr\";" fullword ascii
    $s18 = "initialInUnit[swing] = (1 & augmentWidthOrHeight);" fullword ascii
    $s19 = "var abort = \"WScri\"," fullword ascii
    $s20 = "string = bup[rsubmittable + hasDuplicate + siblings + funescape + pattern];" fullword ascii

  condition:
    uint16(0) == 0x6e6f and
    8 of them
}