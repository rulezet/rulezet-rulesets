rule sig_20160309_85e2c6ba71610d93960bfa9d935a123c {
  meta:
    description = "datamaliciousorder - file 20160309_85e2c6ba71610d93960bfa9d935a123c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abddc9af1be3e00e6d803ed461bce8901ef1a22bf43a87e910504c0231282fc5"

  strings:
    $s1  = "nodeName[rscriptTypeMasked + returnValue](writable, mappedTypes + opener + subtract + toSelector + setter + getResponseHeader + " ascii
    $s2  = "nodeName[rscriptTypeMasked + returnValue](writable, mappedTypes + opener + subtract + toSelector + setter + getResponseHeader + " ascii
    $s3  = "bySet[when + addGetHookIf + always] = ((1 & timeStamp) + -(1 * timeStamp));" fullword ascii
    $s4  = "unit = (((157 - root) * (0 | rtypenamespace) + (84 - finalDataType)), (((40, delay, 76, access) / (9 | pos)), this));" fullword ascii
    $s5  = "match = ajax[rhash + contextBackup + curCSSTop + jQuery](e + then + dataTypeOrTransport);" fullword ascii
    $s6  = "init[triggerHandler + completeDeferred + collection + dataTypeOrTransport + orig](cloneCopyEvent, ((0 | rtypenamespace) | (0 | r" ascii
    $s7  = "init[triggerHandler + completeDeferred + collection + dataTypeOrTransport + orig](cloneCopyEvent, ((0 | rtypenamespace) | (0 | r" ascii
    $s8  = "currentTime[factory](cloneCopyEvent.done(), (0 | realStringObj), (1 + -(timeStamp * 1)));" fullword ascii
    $s9  = "unit[fadeTo + noConflict + $][delegateType + attr](((22571 - fnOut) + (16920 / last)));" fullword ascii
    $s10 = "wrapMap + rsingleTag + fadeOut + nid + setPositiveNumber + clearInterval + status, !(2 < (((document & 31) - (prevUntil | 4)) * " ascii
    $s11 = "cloneCopyEvent = match[cssText + merge + wrapInner + removeData + orig + always + appendTo + stateVal + elements](tmp + matcher)" ascii
    $s12 = "cloneCopyEvent = match[cssText + merge + wrapInner + removeData + orig + always + appendTo + stateVal + elements](tmp + matcher)" ascii
    $s13 = "finalDataType = 55, special = \"Script\", wrapInner = \"v\", parseOnly = \"open\";" fullword ascii
    $s14 = "writable = \"GET\"," fullword ascii
    $s15 = "nodeName[shift + dequeue]();" fullword ascii
    $s16 = "ajax = unit[adown + $];" fullword ascii
    $s17 = "root = 100;" fullword ascii
    $s18 = "dataTypeOrTransport = \"l\", start = \"pt\", wrapMap = \"syst\";" fullword ascii
    $s19 = "init = unit[adown + isSimulated + start][result + responseType + stateVal](uid + truncate + finalText + fixInput + isSuccess);" fullword ascii
    $s20 = "document = 23;" fullword ascii

  condition:
    uint16(0) == 0x6f74 and
    8 of them
}