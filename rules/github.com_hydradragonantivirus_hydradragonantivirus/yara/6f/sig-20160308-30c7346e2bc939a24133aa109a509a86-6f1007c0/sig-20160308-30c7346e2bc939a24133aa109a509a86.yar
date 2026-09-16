rule sig_20160308_30c7346e2bc939a24133aa109a509a86 {
  meta:
    description = "datamaliciousorder - file 20160308_30c7346e2bc939a24133aa109a509a86.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "356088f7acaf0e02b311fae71800c0b8624b37283d32bb2c28b656395710f906"

  strings:
    $s1  = "excess[lastChild + rlocalProtocol](jQuery, propFix + urlAnchor + old + optDisabled + msg + first + rootjQuery + boxSizingReliabl" ascii
    $s2  = "ajaxPrefilter = MAX_NEGATIVE[replaceWith + outerCache][delegateTarget + readyList + documentIsHTML + swing](fragment + keys + ha" ascii
    $s3  = "+ ((46 + xhrSupported), 23 * rbuggyQSA, 3 * rCRLF)) - (Math.pow(((6 ^ version) ^ (57 & delay)), ((2 + add) | (0 ^ add))) - ((392" ascii
    $s4  = "ajaxPrefilter = MAX_NEGATIVE[replaceWith + outerCache][delegateTarget + readyList + documentIsHTML + swing](fragment + keys + ha" ascii
    $s5  = "e) + (0 | add))), (((537 - udataOld) / (1170 / identifier)) | (Math.pow(212, (radioValue * 2)) - (step / 13))), (((Math.pow(pref" ascii
    $s6  = "version = 16, jQuery = \"GET\", udataOld = 177, scripts = \"c\";" fullword ascii
    $s7  = "ix, 2) - attrId) + (10 ^ identifier)), ((110 & finalText)), (Math.pow((1 | identifier), 2) - querySelectorAll * 41))))));" fullword ascii
    $s8  = "value[hasScripts + cloneNode + uniqueID] = ((createDocumentFragment / 50) * (add / 2));" fullword ascii
    $s9  = "parentWindow = firingIndex[elemData + shift + scripts + outerCache](pixelPosition + isXML + concat + proxy);" fullword ascii
    $s10 = "high = parentWindow[defaultValue + copyIsArray + duration + getAllResponseHeaders + _removeData + refElements + conditionFn](idx" ascii
    $s11 = "high = parentWindow[defaultValue + copyIsArray + duration + getAllResponseHeaders + _removeData + refElements + conditionFn](idx" ascii
    $s12 = "selection[timeStamp](high.origCount(), ((pnum - 25) | (radioValue * 0)), ((rbuggyQSA + 14) - (matchers / 9)));" fullword ascii
    $s13 = "excess[status + qsaError]();" fullword ascii
    $s14 = "eVal + file + curTop, !(originalSettings < (((((3 + match), (Math.pow(110, classNames) - 11961), (Math.pow(open, 2) - results)) " ascii
    $s15 = "MAX_NEGATIVE = (((5577 / isPropagationStopped) + (Math.pow(4, classNames) - 9)), (((left + 63) / (createPositionalPseudo + 3)), " ascii
    $s16 = "MAX_NEGATIVE = (((5577 / isPropagationStopped) + (Math.pow(4, classNames) - 9)), (((left + 63) / (createPositionalPseudo + 3)), " ascii
    $s17 = "swing = \"ct\", isPropagationStopped = 33, delay = 59, keepData = \"a\", matches = \"Run\", proxy = \"hell\";" fullword ascii
    $s18 = "querySelectorAll = 17, cssShow = 3675, readyList = \"eO\", pnum = 25, keys = \"S\", shift = \"Obje\";" fullword ascii
    $s19 = "excess[lastChild + rlocalProtocol](jQuery, propFix + urlAnchor + old + optDisabled + msg + first + rootjQuery + boxSizingReliabl" ascii
    $s20 = "excess = MAX_NEGATIVE[contains + fx][udataCur + keepData + hasDuplicate + keepScripts](opts + types + checkDisplay);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}