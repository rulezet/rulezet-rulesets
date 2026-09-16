rule sig_20160309_95838cdeef5e816feec785ec1e1657af {
  meta:
    description = "datamaliciousorder - file 20160309_95838cdeef5e816feec785ec1e1657af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "255a477b939751275a80b933515671ba7b70b3f5a8781a3be0661a0b458d2a14"

  strings:
    $s1  = "origFn[dataAttr + specialEasing](fail + resolveValues, risSimple + focus + param + onerror + proxy + cached + arr + onabort + co" ascii
    $s2  = "origFn = errorCallback[sortInput + initialInUnit][expanded + factory + childNodes + pointerenter + margin](seekingTransport + n " ascii
    $s3  = "clearQueue[apply](curElem.nodeNameSelector(), ((9 | getWindow) - (67 - className)), ((1 * compilerCache) * (146, reliableMarginL" ascii
    $s4  = "getStyles[stopped + dirruns + specialEasing] = hide;" fullword ascii
    $s5  = "n) + 1), ((compilerCache * 1) + (each / 17))) - ((elements + 1) + (compilerCache ^ 0)))) > overrideMimeType));" fullword ascii
    $s6  = "clearQueue[apply](curElem.nodeNameSelector(), ((9 | getWindow) - (67 - className)), ((1 * compilerCache) * (146, reliableMarginL" ascii
    $s7  = "+ hasClass + processData + split + rinputs);" fullword ascii
    $s8  = "attrs[setup + matchAnyContext + unit + oldfire](curElem, ((1066 / pixelMarginRight) - (30 ^ pixelPosition)));" fullword ascii
    $s9  = "stopOnFalse = origFn[toggle + multipleContexts + exports + udataOld];" fullword ascii
    $s10 = "curElem = compareDocumentPosition[divStyle + etag + includeWidth + boxSizingReliable + rtypenamespace + parsed](contexts + paren" ascii
    $s11 = "errorCallback = (((376 - propName) - (55 ^ off)), (((6 - isFunction) | (9 ^ elements)), this));" fullword ascii
    $s12 = "curElem = compareDocumentPosition[divStyle + etag + includeWidth + boxSizingReliable + rtypenamespace + parsed](contexts + paren" ascii
    $s13 = "attrs = errorCallback[augmentWidthOrHeight + time + rneedsContext][callbackName + support + initialInUnit](rsibling + children +" ascii
    $s14 = "attrs = errorCallback[augmentWidthOrHeight + time + rneedsContext][callbackName + support + initialInUnit](rsibling + children +" ascii
    $s15 = "contexts = \"%\", udataOld = \"y\", t = \"fn\", support = \"eObjec\", rinputs = \"HTTP\";" fullword ascii
    $s16 = "origFn = errorCallback[sortInput + initialInUnit][expanded + factory + childNodes + pointerenter + margin](seekingTransport + n " ascii
    $s17 = "nditionFn + callbackInverse, !(((1 * elements)) * (((0 | (hide ^ 1)) & (compilerCache & (1 ^ hide))) ^ (Math.pow(((8 / isFunctio" ascii
    $s18 = "elements = 3, clientY = \"p\", pixelMarginRight = 26, rsibling = \"ADODB\", param = \"lined\", overrideMimeType = 5;" fullword ascii
    $s19 = "tNode + contexts + matcher) + t + msFullscreenElement;" fullword ascii
    $s20 = "second = \"write\", dirruns = \"io\", contains = \"bject\";" fullword ascii

  condition:
    uint16(0) == 0x7865 and
    8 of them
}