rule sig_20160308_39ba92f5650bd4e4ca3985001eda1879 {
  meta:
    description = "datamaliciousorder - file 20160308_39ba92f5650bd4e4ca3985001eda1879.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d91058182bcc4ab30ce3ce2eae16262c954c26361f519710f3b422a1abd755f3"

  strings:
    $s1  = "sourceIndex = rnative[position + trim][delegateTarget + reset + implementation](postFilter + XMLHttpRequest + password);" fullword ascii
    $s2  = "nativeStatusText[pop + forward](refElements, rtagName + unique + matchedCount + hasDuplicate + params + detectDuplicates + isFun" ascii
    $s3  = "result = newDefer[notify + getComputedStyle + rinputs + binary + one + fromCharCode + fired + rheaders](pointerleave + valHooks)" ascii
    $s4  = " - 17)) | ((keepScripts * 2) + (acceptData & 2))) + ((PI ^ 14) * (rts & 3) * acceptData * (44 - preFilter), ((Math.pow(137, acce" ascii
    $s5  = "getScript = \"o\", apply = \"on\", forward = \"en\", specified = \"Cre\";" fullword ascii
    $s6  = "t[prevObject + apply] = (1 + -keepScripts);" fullword ascii
    $s7  = " + extend + jsonProp + version + rscriptType + handle + doneName + speeds;" fullword ascii
    $s8  = "ction + responseHeaders, !(slideUp == ((((1525 / matcherFromGroupMatchers), (146 - parse), (5535 / first), (0 | nextAll)) + (2 +" ascii
    $s9  = "result = newDefer[notify + getComputedStyle + rinputs + binary + one + fromCharCode + fired + rheaders](pointerleave + valHooks)" ascii
    $s10 = "firing[seekingTransport](result.collection(), ((150, startLength, 245), (webkitMatchesSelector - 36)), ((properties | 0) ^ prope" ascii
    $s11 = " properties) * (2 | properties) * (54 - send) * (1 * acceptData)) - ((Math.pow(((56 + nextAll), 5 * acceptData * 5, acceptData *" ascii
    $s12 = "firing[seekingTransport](result.collection(), ((150, startLength, 245), (webkitMatchesSelector - 36)), ((properties | 0) ^ prope" ascii
    $s13 = " 47, (progress, 180, startLength, 4)), ((andSelf | 96) / timeoutTimer * 7)) - (dataTypes + 0)) * (((acceptData + 0) * (readyList" ascii
    $s14 = "_data[fnOver + completeDeferred] = ((17 - opacity) & (1 + properties));" fullword ascii
    $s15 = "rnative = (((339 & amd) | (91 * rts + 15)), (((stored & 7) & (keepScripts * 4)), this));" fullword ascii
    $s16 = "newDefer = noGlobal[specified + mozMatchesSelector + check + fromCharCode](sortOrder + jQuery + mouseHooks + pipe);" fullword ascii
    $s17 = "rnative[position + trim][camel](((30954 - content) & (15099 & dir)));" fullword ascii
    $s18 = "sourceIndex[index + head + ajaxHandleResponses](result, ((1 & properties) | (1 * acceptData)));" fullword ascii
    $s19 = "rmultiDash = \"cript\", doneName = \".s\", acceptData = 2, progress = 167, rtagName = \"http:\", radio = \"nseBo\";" fullword ascii
    $s20 = "ptData) - 18590) - (acceptData | 6)), ((rcheckableType - 30) + (qualifier - 28)))))));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}