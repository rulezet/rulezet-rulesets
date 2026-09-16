rule sig_20160308_b5bc1fde7fe94c90490964926d789565 {
  meta:
    description = "datamaliciousorder - file 20160308_b5bc1fde7fe94c90490964926d789565.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf9248a3414ce0ffa598dc1b597b4718bfcf37bebf96e42d40e3624449f5cd44"

  strings:
    $s1  = "handlerQueue[ajaxHandleResponses](ajaxSetup + rwhitespace, iframe + newDefer + m + callbackExpect + dataAndEvents + push_native " ascii
    $s2  = "+ getAllResponseHeaders + after + _data + setOffset + processData + sortOrder + cssPrefixes + focusin + matchIndexes + hasFocus," ascii
    $s3  = "createOptions = \"B.\", flatOptions = \"S\", newDefer = \":/\", password = \"wri\", getComputedStyle = \"p\", onerror = \"ateO\"" ascii
    $s4  = "conv[password + args + Expr](handlerQueue[hasData + dequeue + processData + children + superMatcher]);" fullword ascii
    $s5  = "col[nidselect](input.amd(), (token * 43, (each, 126, proxy), (86 ^ stopPropagation), (1 + -cloneCopyEvent)), ((155, test) / (53 " ascii
    $s6  = "col[nidselect](input.amd(), (token * 43, (each, 126, proxy), (86 ^ stopPropagation), (1 + -cloneCopyEvent)), ((155, test) / (53 " ascii
    $s7  = "conv = originalProperties[guid + copyIsArray + beforeunload + _evalUrl][getClientRects + stop + isXML](delegate + source + conte" ascii
    $s8  = "input = getElementsByName[getAttributeNode + sortStable + rsubmittable + parseHTML + curCSSLeft + rcomma](visibility + parseJSON" ascii
    $s9  = "input = getElementsByName[getAttributeNode + sortStable + rsubmittable + parseHTML + curCSSLeft + rcomma](visibility + parseJSON" ascii
    $s10 = " originalProperties[wrapMap + _evalUrl][win + getComputedStyle](((unit | 7) * (once ^ 0) + (onlyHandlers & 7)));" fullword ascii
    $s11 = " & (((token + 1) * (modified, 229, siblingCheck)) | 5 * once * (1 * rnotwhite) * (35, defer, 84, rnotwhite))) - (((1 | test) ^ (" ascii
    $s12 = "3 * token + 2)) | ((style | 80) - (updateFunc * 3 + token))) * (((37, once) | (1 + -cloneCopyEvent)) - (1 + (boolHook, 0))))));" fullword ascii
    $s13 = "conv = originalProperties[guid + copyIsArray + beforeunload + _evalUrl][getClientRects + stop + isXML](delegate + source + conte" ascii
    $s14 = "getJSON[contexts + rbuggyQSA + arg] = ((1 & cloneCopyEvent) & (0 | test));" fullword ascii
    $s15 = "originalProperties = (((194, els, 21) + (fadeOut + 26)), (((removeAttr * 3 + actualDisplay) - (2079 / hidden)), this));" fullword ascii
    $s16 = " !(8 < (((Math.pow((once * 3 * rnotwhite * 3 - (caption / 47)), (cloneCopyEvent * 2)) - ((left & 1407) | (originAnchor ^ 1179)))" ascii
    $s17 = "token = 5, win = \"Slee\", fadeOut = 226, dir = \"ready\";" fullword ascii
    $s18 = " + checkClone) + rquery + rhtml + Expr + append + protocol;" fullword ascii
    $s19 = "originalProperties[expanded + removeChild][flatOptions + firstElementChild](((_load + 12318) & (ownerDocument * 31 + stopPropaga" ascii
    $s20 = "ntType + createOptions + code);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}