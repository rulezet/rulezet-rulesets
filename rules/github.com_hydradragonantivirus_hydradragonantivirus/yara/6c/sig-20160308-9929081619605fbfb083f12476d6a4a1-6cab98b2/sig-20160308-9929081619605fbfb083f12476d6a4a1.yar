rule sig_20160308_9929081619605fbfb083f12476d6a4a1 {
  meta:
    description = "datamaliciousorder - file 20160308_9929081619605fbfb083f12476d6a4a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8a6c784d395f17f535d227d7e390b2a514b7fc2fa3ed68348150127d26dc659"

  strings:
    $s1  = "lastModified[checkNonElements + groups](qsaError + scrollTop, needsContext + events + proxy + hasScripts + pointerleave + rnativ" ascii
    $s2  = ") & ((3 * random * 3 * computed / (714 / getElementsByClassName)) | ((Math.pow(8, computed) - 49)))))));" fullword ascii
    $s3  = "old = (((3522 | props) / (4 + serializeArray)), (((Math.pow(108, computed) - 11463), (dir ^ 18)), this));" fullword ascii
    $s4  = "old[parentOffset + rfocusable][type + mimeType](((192 / pageXOffset) | (Math.pow(10131, computed) - 102622161)));" fullword ascii
    $s5  = "lastModified[checkNonElements + groups](qsaError + scrollTop, needsContext + events + proxy + hasScripts + pointerleave + rnativ" ascii
    $s6  = "var inPage = \"%TEMP%\"," fullword ascii
    $s7  = "boxSizingReliableVal = els[rtypenamespace + checkDisplay + types + writable + contentType](inPage + oMatchesSelector) + setup + " ascii
    $s8  = "boxSizingReliableVal = els[rtypenamespace + checkDisplay + types + writable + contentType](inPage + oMatchesSelector) + setup + " ascii
    $s9  = "fx = 48, getById = 58, complete = \"W\";" fullword ascii
    $s10 = "button = old[maxWidth + copyIsArray + binary];" fullword ascii
    $s11 = "qsaError = \"G\", checkNonElements = \"op\", props = 424, binary = \"pt\";" fullword ascii
    $s12 = "old[rnoInnerhtml + fadeTo + always][addGetHookIf + lname + mimeType](((detach | 100) & dir * 2 * getElementsByClassName));" fullword ascii
    $s13 = "lastModified = old[parentOffset + rfocusable][progress + matchers + adjustCSS + push](returned + sibling + prevAll);" fullword ascii
    $s14 = "source + createInputPseudo;" fullword ascii
    $s15 = "els = button[clientTop + setter + progressContexts + push](maxWidth + checkbox + nodeIndex + srcElements);" fullword ascii
    $s16 = "disable[mimeType + current + realStringObj] = ((easing & 1) * (strAbort / 19));" fullword ascii
    $s17 = "inArray[beforeunload](boxSizingReliableVal.jsonp(), (130, win, 0), (easing * (140, strAbort)));" fullword ascii
    $s18 = "dataTypeExpression = old[complete + soFar + copyIsArray + binary][compareDocumentPosition + uid + gotoEnd + setAttribute](fcamel" ascii
    $s19 = "dataTypeExpression[version](lastModified[duplicates + mimeType + rsubmittable + destElements + rnamespace]);" fullword ascii
    $s20 = "while(lastModified[nodes + key + oldCallbacks] < ((easing ^ 5) ^ (easing * 0))) {" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    8 of them
}