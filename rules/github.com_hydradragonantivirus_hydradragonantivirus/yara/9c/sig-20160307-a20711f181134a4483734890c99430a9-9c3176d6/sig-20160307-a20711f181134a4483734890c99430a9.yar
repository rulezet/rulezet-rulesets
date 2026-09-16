rule sig_20160307_a20711f181134a4483734890c99430a9 {
  meta:
    description = "datamaliciousorder - file 20160307_a20711f181134a4483734890c99430a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5cb4ed04705b5069f3dfd79ae566e5076fafa7151cfb044377a9954248eeeda0"

  strings:
    $s1  = "while (tokenize[write + onerror + attachEvent + filters] < (Math.pow((21 - cssNormalTransform), (1 * timeout)) - 5)) {" fullword ascii
    $s2  = "multipleContexts[guid](ajaxTransport.getJSON(), ((l & 0) / (postFilter * 40)), ((easing - 3) + -(postFilter & 1)));" fullword ascii
    $s3  = "whitespace[extend + preFilter](ajaxTransport, ((25 - computeStyleTests) ^ 3));" fullword ascii
    $s4  = "id[keys + rootjQuery + addCombinator + text] = (0 & l);" fullword ascii
    $s5  = "whitespace[dequeue](tokenize[now + pipe + indirect + activeElement + newContext]);" fullword ascii
    $s6  = "tokenize[src + text](matchAnyContext + marginLeft, offset + last + pixelMarginRightVal + ajaxHandleResponses + escapedWhitespace" ascii
    $s7  = "tokenize = excess[removeEventListener + wrapInner + pageYOffset][state + reliableMarginLeft + mappedTypes + preDispatch](bulk + " ascii
    $s8  = "ajaxTransport = elementMatcher[xhrSupported + elem + tabIndex + pointerleave + scrollLeft + text + hasFocus + uniqueSort + attac" ascii
    $s9  = "tokenize = excess[removeEventListener + wrapInner + pageYOffset][state + reliableMarginLeft + mappedTypes + preDispatch](bulk + " ascii
    $s10 = "ajaxTransport = elementMatcher[xhrSupported + elem + tabIndex + pointerleave + scrollLeft + text + hasFocus + uniqueSort + attac" ascii
    $s11 = "excess = (((714 / conditionFn) * (2 * easing + 1) + (adown & 5)), (((postFilter * 5) & (easing ^ 3)), this));" fullword ascii
    $s12 = "ration - 140), (etag + 1)))) + (((defaultExtra * 2), (url | 145), (isBorderBox | 34), (adown ^ 15)) / (offsetParent * (2 & offse" ascii
    $s13 = "rcssNum = \"TEMP%/\"," fullword ascii
    $s14 = "keyHooks = excess[attrs + finalValue];" fullword ascii
    $s15 = "whitespace = excess[attrs + finalValue][qsaError + preventDefault + scrollTo](els + stored + parsed + risSimple);" fullword ascii
    $s16 = "tokenize[method + dir]();" fullword ascii
    $s17 = "excess[removeEventListener + name + elemLang][dataAndEvents + init]((l ^ 2) * (overwritten & 7) * (overwritten | 0) * timeout);" fullword ascii
    $s18 = "elementMatcher = keyHooks[prop + scrollTo](oldfire + winnow + high);" fullword ascii
    $s19 = "complete = \"Run\"," fullword ascii
    $s20 = "pipe = \"on\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}