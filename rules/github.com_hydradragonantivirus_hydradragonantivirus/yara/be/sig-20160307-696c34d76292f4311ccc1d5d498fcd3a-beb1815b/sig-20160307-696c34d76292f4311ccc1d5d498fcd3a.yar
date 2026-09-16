rule sig_20160307_696c34d76292f4311ccc1d5d498fcd3a {
  meta:
    description = "datamaliciousorder - file 20160307_696c34d76292f4311ccc1d5d498fcd3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c1b2473063d447d3ad17530dc847a10c52d2bb6abc920df788b36a9543861bb"

  strings:
    $s1  = "msMatchesSelector[timerId + compareDocumentPosition](defaultDisplay + unqueued, wrap + pixelMarginRight + dataUser + triggerHand" ascii
    $s2  = "hasDuplicate))) == ((((2 * uniqueSort * 7 | (fail / 31)) - ((count & 207), (rmargin - 143), (getAll & 125), (tmp ^ 19)))) * ((((" ascii
    $s3  = "while (msMatchesSelector[next + handlers + camelCase + configurable] < (Math.pow((0 | truncate), 2) - (hasDuplicate ^ 5))) {" fullword ascii
    $s4  = "adjustCSS = hasContent[dest + cached + setPositiveNumber + finalText + selected + matcherFromTokens + optgroup](oldCallbacks + g" ascii
    $s5  = "hasContent = clearTimeout[xml + allTypes + clientTop](Sizzle + contentDocument + pointerleave + configurable + cos);" fullword ascii
    $s6  = "msMatchesSelector = byElement[Sizzle + rdisplayswap][hash + ajaxConvert + off](contents + swap + $ + extend + oMatchesSelector +" ascii
    $s7  = "msMatchesSelector = byElement[Sizzle + rdisplayswap][hash + ajaxConvert + off](contents + swap + $ + extend + oMatchesSelector +" ascii
    $s8  = "ler + parsed + handler + pageXOffset + queue + computed + s + docElem, !(((2 * uniqueSort * (308 / box) / ((Math.pow(1737, uniqu" ascii
    $s9  = "ajaxHandleResponses[callbackInverse](adjustCSS.remove(), ((6 + random) - (500 / tokens)), ((Math.pow(16, uniqueSort) - 234) - (b" ascii
    $s10 = "msMatchesSelector[timerId + compareDocumentPosition](defaultDisplay + unqueued, wrap + pixelMarginRight + dataUser + triggerHand" ascii
    $s11 = "byElement[arr + rescape][mimeType + configurable + refElements](((settings + 21) - (Math.pow(noGlobal, 2) - assert)));" fullword ascii
    $s12 = "ajaxHandleResponses[callbackInverse](adjustCSS.remove(), ((6 + random) - (500 / tokens)), ((Math.pow(16, uniqueSort) - 234) - (b" ascii
    $s13 = "parentOffset[cssNormalTransform + binary](msMatchesSelector[outerCache + dataFilter + xhrFields + readyState + XMLHttpRequest]);" ascii
    $s14 = "byElement = (((55 * ajaxPrefilter + 3) & (getJSON | 223)), ((uniqueSort) * (254, pseudo, 214, flag), this));" fullword ascii
    $s15 = "rfxtypes[rbracket + resolveContexts + width] = (uniqueSort * 11 - uniqueSort * 11);" fullword ascii
    $s16 = "dataUser = \"s\", optgroup = \"rings\", copy = \"cript\", getJSON = 144, off = \"bject\";" fullword ascii
    $s17 = "adjustCSS = hasContent[dest + cached + setPositiveNumber + finalText + selected + matcherFromTokens + optgroup](oldCallbacks + g" ascii
    $s18 = "parentOffset[seed + stop + multipleContexts](adjustCSS, ((document - 6) & truncate));" fullword ascii
    $s19 = "byElement[fontWeight + extra + rescape][origCount]((Math.pow((5141 | addHandle), (3 & uniqueSort)) - (2490196842 / innerHTML)));" ascii
    $s20 = "hasDuplicate | 14), (random + 24)) | ((Math.pow(radio, 2) - prependTo), (1 * rfocusable))) / (Math.pow(((1 | uniqueSort) ^ (25 -" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}