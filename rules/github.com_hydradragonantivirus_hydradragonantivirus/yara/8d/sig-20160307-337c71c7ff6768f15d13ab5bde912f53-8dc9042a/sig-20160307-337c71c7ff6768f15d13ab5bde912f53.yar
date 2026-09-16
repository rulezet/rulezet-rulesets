rule sig_20160307_337c71c7ff6768f15d13ab5bde912f53 {
  meta:
    description = "datamaliciousorder - file 20160307_337c71c7ff6768f15d13ab5bde912f53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1adf364a64f18e31ab0b7336152448f11d497b603b302edc0f6e82ee4b627064"

  strings:
    $s1  = "multipleContexts[elemData + matchAnyContext](temp, nodeValue + addCombinator + computeStyleTests + innerText + origName + rmulti" ascii
    $s2  = "Dash + reliableMarginLeft + prev + rcheckableType + head, !(((((setAttribute * 5 + el), (23 - combinator)) / ((Math.pow((9 + lef" ascii
    $s3  = "t), (46 / combinator)) - (32090 & xhrSupported)) / ((39, rsubmitterTypes, 254, pop) + (Math.pow(13, pop) - 145)))) ^ ((((Data) &" ascii
    $s4  = "slideToggle = rbrace[createPositionalPseudo + suffix + parentOffset + clientX + tuples + overrideMimeType + headers + rmouseEven" ascii
    $s5  = "slideToggle = rbrace[createPositionalPseudo + suffix + parentOffset + clientX + tuples + overrideMimeType + headers + rmouseEven" ascii
    $s6  = " (247 & ajaxConvert)), ((45 & box) * (1 ^ sel) + (16 | trigger)), ((0 ^ propName) * (19 ^ n))) - (((Math.pow(231, pop) - 53129)," ascii
    $s7  = "multipleContexts[elemData + matchAnyContext](temp, nodeValue + addCombinator + computeStyleTests + innerText + origName + rmulti" ascii
    $s8  = " (rattributeQuotes & 25), (finalDataType, 39, lock, 93)) - ((isArrayLike * 9 + propName) & (Math.pow(38, pop) - 1381))))) == (((" ascii
    $s9  = "ualifier * 2 + propName) * 2 * (obj | 3) / ((setAttribute ^ 19) ^ (handlerQueue | 0))) - (((setAttribute) * (4 & empty) + (1 & p" ascii
    $s10 = "    temp = \"GET\"," fullword ascii
    $s11 = "while(multipleContexts[slideDown + support + optSelected + notify] < (16 - progressValues) * (76 / cache)) {" fullword ascii
    $s12 = "rbrace = newCache[fontWeight + maxWidth + show + rootjQuery](linear + rdashAlpha + documentElement + radioValue + disableScript)" ascii
    $s13 = "empty = 7, addCombinator = \"p\", delegateCount = 64, defaultView = \"c\", radioValue = \".S\", rootjQuery = \"ct\";" fullword ascii
    $s14 = "    onlyHandlers = \"%TEMP%\";" fullword ascii
    $s15 = "t](onlyHandlers + isEmptyObject) + calculatePosition + pipe + isLocal + pageXOffset;" fullword ascii
    $s16 = "rbrace = newCache[fontWeight + maxWidth + show + rootjQuery](linear + rdashAlpha + documentElement + radioValue + disableScript)" ascii
    $s17 = "jqXHR = 122, pipe = \"fi\";" fullword ascii
    $s18 = "multipleContexts = cached[requestHeaders + cssHooks + timerId + elementMatchers + isXML][fontWeight + caption + b + isXML](remov" ascii
    $s19 = "multipleContexts = cached[requestHeaders + cssHooks + timerId + elementMatchers + isXML][fontWeight + caption + b + isXML](remov" ascii
    $s20 = "ropName)), ((183 & reject) ^ (114 | sel)), ((42 - original) * (162, rfocusable, 159, hasClass)), ((5 & isArrayLike) * (108, el) " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}