rule sig_20160307_d205da9f4a51a9ef10dd62aaf92a7bc9 {
  meta:
    description = "datamaliciousorder - file 20160307_d205da9f4a51a9ef10dd62aaf92a7bc9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dd612f33d1121b0ac760d81e4ed0fa9c6dfd5aee9224c83d101dc066f8660de"

  strings:
    $x1  = "onabort[extend](cur, udataCur + namespaces + srcElements + converters + scripts + isSimulated + groups + isSuccess + requestHead" ascii
    $s2  = "while(onabort[gotoEnd + manipulationTarget + type] < ((22 - getBoundingClientRect) ^ (4 ^ visible))) {" fullword ascii
    $s3  = "matched = (((Math.pow(8, visible) - 50)), (((eventPath / 6) ^ (getAll & 0)), this));" fullword ascii
    $s4  = "oMatchesSelector[parent](defaultDisplay.jqXHR(), ((matchContext - 27) / (Math.pow(window, 2) - protocol)), (0 ^ getAll));" fullword ascii
    $s5  = "etAll))) - ((Math.pow(3, visible) - 4) * (visible ^ 1) & ((getAll / 31) ^ (write, 127, mouseHooks))))) == (((((288 / ajaxHandleR" ascii
    $s6  = "Data = matched[isXMLDoc + p][createTween + rscriptType + fn + rbuggyQSA](rnoContent + namespace);" fullword ascii
    $s7  = "onabort[extend](cur, udataCur + namespaces + srcElements + converters + scripts + isSimulated + groups + isSuccess + requestHead" ascii
    $s8  = "defaultDisplay = promise[pointerleave + complete + dataTypeExpression + input + getComputedStyle + xhrSuccessStatus](udataOld + " ascii
    $s9  = "Data[removeEventListener + onlyHandlers](onabort[valueIsBorderBox + readyState + rkeyEvent + rinputs]);" fullword ascii
    $s10 = "- (((Math.pow((matchIndexes & 55), (visible + 0)) - (addEventListener & 2033)) - (visible * 2 * visible * (2 + visible) + (6 | g" ascii
    $s11 = "defaultDisplay = promise[pointerleave + complete + dataTypeExpression + input + getComputedStyle + xhrSuccessStatus](udataOld + " ascii
    $s12 = "esponses) + (2 * teardown + 1)) * (progress) + ((20, tween, 189) / (queue - 40))) - (((window + 0) ^ (rmargin, 254, rhash)) & ((" ascii
    $s13 = "createHTMLDocument), (Math.pow(67, visible) - 4418))) + ((guaranteedUnique * (1 + teardown)) + ((230, rwhitespace) | (7 * visibl" ascii
    $s14 = "unbind) + booleans + msg + transports + hasData;" fullword ascii
    $s15 = "e + 2)))), (((progress / 5) * (getAll | 0)) ^ ((guaranteedUnique + 0) * visible)))));" fullword ascii
    $s16 = "createInputPseudo[clientX + text] = (getAll ^ 0);" fullword ascii
    $s17 = "gotoEnd = \"r\", class2type = \"cript\", manipulationTarget = \"eady\", complete = \"Envi\", serializeArray = \"type\";" fullword ascii
    $s18 = "onabort = matched[callbackContext + isArray][createTween + rsingleTag + traditional](tweener + getWindow + transports + marginDi" ascii
    $s19 = "onabort = matched[callbackContext + isArray][createTween + rsingleTag + traditional](tweener + getWindow + transports + marginDi" ascii
    $s20 = "ersNames + wrapAll + returnFalse, !((((((specialEasing ^ 123) - (isPropagationStopped * 7 + newContext)) * ((2 + visible) ^ (144" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}