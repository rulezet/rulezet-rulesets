rule sig_20160308_1052e228607886fd7497cc615f29b7dd {
  meta:
    description = "datamaliciousorder - file 20160308_1052e228607886fd7497cc615f29b7dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8294f434d6f76fccaa29f584b12a4a2b29f5263b5bf90cba0419f97fa9479c8d"

  strings:
    $s1  = "while(seekingTransport[fixHook + register + postMap + max] < (Math.pow((matcherOut | 1), (el - 40)) - (rhtml | 1))) {" fullword ascii
    $s2  = "timerId[cssShow + off][rmsPrefix]((Math.pow((resolve & 118), (script - 47)) - matcherOut * 2 * matcherOut * 3 * matcherOut * 2 *" ascii
    $s3  = "timerId[cssShow + off][rmsPrefix]((Math.pow((resolve & 118), (script - 47)) - matcherOut * 2 * matcherOut * 3 * matcherOut * 2 *" ascii
    $s4  = "clearQueue = timerId[_evalUrl + removeAttr + focusin][collection + safeActiveElement + getScript + focusin](prev + parseJSON + t" ascii
    $s5  = "clearQueue = timerId[_evalUrl + removeAttr + focusin][collection + safeActiveElement + getScript + focusin](prev + parseJSON + t" ascii
    $s6  = "seekingTransport[caption](parent + hooks, getAllResponseHeaders + rbracket + offset + status + nodeValue + focusin + attributes " ascii
    $s7  = "clearQueue[rkeyEvent](seekingTransport[rmouseEvent + argument + valueIsBorderBox]);" fullword ascii
    $s8  = " ^ mimeType))) + ((((45 - dataTypes) | (Math.pow(25, matcherOut) - 585)) / ((noGlobal - 22) * (contexts & 3) + (Math.pow(context" ascii
    $s9  = "imeType ^ 1))) / (((assert - 61), (clearTimeout - 123), (Math.pow(createPositionalPseudo, 2) - pdataOld), (1 & removeData)) * (1" ascii
    $s10 = "seekingTransport = timerId[_evalUrl + prevObject][beforeSend + fixHook + swap + safeActiveElement + top](progressContexts + rsub" ascii
    $s11 = "radioValue = timerId[excess + getWindow + focusin];" fullword ascii
    $s12 = "seekingTransport[caption](parent + hooks, getAllResponseHeaders + rbracket + offset + status + nodeValue + focusin + attributes " ascii
    $s13 = "s, 2) - originalProperties))) + -((1 ^ mimeType) & (48 / node)))) == 1));" fullword ascii
    $s14 = "seekingTransport = timerId[_evalUrl + prevObject][beforeSend + fixHook + swap + safeActiveElement + top](progressContexts + rsub" ascii
    $s15 = "timerId[scriptCharset + focusin][animate + classCache](((315000 / hasFocus)));" fullword ascii
    $s16 = "script = 49;" fullword ascii
    $s17 = "valueIsBorderBox = \"eBody\", collection = \"Create\", keepScripts = \"n\", animated = \"fir\", prev = \"AD\";" fullword ascii
    $s18 = "expand = useCache[stopped + udataCur + keepScripts + lang + rdashAlpha + uniqueCache + constructor](colgroup + defaultExtra + lo" ascii
    $s19 = "expand = useCache[stopped + udataCur + keepScripts + lang + rdashAlpha + uniqueCache + constructor](colgroup + defaultExtra + lo" ascii
    $s20 = "clearQueue[selection + siblingCheck + attrHandle](expand, ((2 + mimeType)));" fullword ascii

  condition:
    uint16(0) == 0x6f6e and
    8 of them
}