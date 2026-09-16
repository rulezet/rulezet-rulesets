rule sig_20160309_b30476407e917dd9b57e34ca84526f3a {
  meta:
    description = "datamaliciousorder - file 20160309_b30476407e917dd9b57e34ca84526f3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b8bccb352251b43213320575427f58600e71530b0860a727a73a3f606e37964"

  strings:
    $x1  = "mozMatchesSelector[funcName](cssShow, key + add + curValue + cloneNode + fragment + curElem + stored + propFix + maxIterations +" ascii
    $x2  = "th.pow(((Math.pow(cssHooks, 2) - bySet) - 17 * support) * (1 * l), ((0 ^ manipulationTarget) * ((Math.pow(8, l) - 54) - (script " ascii
    $s3  = " clearInterval + init + fx + delegateTarget + raw + duplicates + configurable + styles, !(6 == (((Math.pow(((identifier - 25) & " ascii
    $s4  = "(hasOwn ^ 145)), ((manipulationTarget & 1) * (support & 2))) - ((allTypes + 28712) - support * 1847 * l)), (((19, invert, 104) +" ascii
    $s5  = " (completeDeferred | 4)) + ((stop / 35) & (Math.pow(mouseenter, 2) - reliableMarginRight))), ((53 & host) - (19 * l + 3))) & (Ma" ascii
    $s6  = "tokenize = (((116 & detectDuplicates), (128 ^ pushStack), (68 + rscriptTypeMasked), (46 & createElement)), (((196, _data) * (0 ^" ascii
    $s7  = "mozMatchesSelector = tokenize[qsaError + visibility + j][acceptData + rhash + button + statusCode](rnoInnerhtml + doc + resolveC" ascii
    $s8  = "mozMatchesSelector = tokenize[qsaError + visibility + j][acceptData + rhash + button + statusCode](rnoInnerhtml + doc + resolveC" ascii
    $s9  = "delegateTarget = \"lo\", stop = 4445;" fullword ascii
    $s10 = "arr[selection + whitespace + PI + rcomma](push, ((16 * support + 13), support * 29, l));" fullword ascii
    $s11 = "arr = tokenize[condense + implicitRelative + cloneNode][nodeIndex + toSelector + width + push_native](after + load + parsed + co" ascii
    $s12 = "converters = tokenize[qsaError + visibility + implicitRelative + cloneNode];" fullword ascii
    $s13 = "hasOwnProperty = converters[err + pixelMarginRight + lname + bool + push_native](getJSON + pixelMarginRightVal + xhrSuccessStatu" ascii
    $s14 = "hasOwnProperty = converters[err + pixelMarginRight + lname + bool + push_native](getJSON + pixelMarginRightVal + xhrSuccessStatu" ascii
    $s15 = "ajax = 6, hasOwn = 39, rscriptTypeMasked = 42, cloneNode = \"t\", selection = \"saveT\", rhash = \"eO\";" fullword ascii
    $s16 = "/ 23)))) - (((ajax & 7) + (code - 34)) | ((removeProp + 1) - (createDocumentFragment, 151, pushStack)))))));" fullword ascii
    $s17 = "soFar = \".scr\";" fullword ascii
    $s18 = "mozMatchesSelector[handle + bool + hash]();" fullword ascii
    $s19 = "arr = tokenize[condense + implicitRelative + cloneNode][nodeIndex + toSelector + width + push_native](after + load + parsed + co" ascii
    $s20 = " _data) + (55, support)), this));" fullword ascii

  condition:
    uint16(0) == 0x6361 and
    1 of ($x*) and 4 of them
}