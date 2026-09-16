rule sig_20160308_df7316910bcd715ea9121b6a3a715c0b {
  meta:
    description = "datamaliciousorder - file 20160308_df7316910bcd715ea9121b6a3a715c0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bae137954106a93f1430a9d6de0e0d1497fc475e50c8ad4b09bce57e3b89999"

  strings:
    $s1  = "initialInUnit[method + prefix] = ((Math.pow(36, prefilterOrFactory) - 1256), (keyHooks - 123), (Math.pow(ownerDocument, 2) - run" ascii
    $s2  = "initialInUnit[method + prefix] = ((Math.pow(36, prefilterOrFactory) - 1256), (keyHooks - 123), (Math.pow(ownerDocument, 2) - run" ascii
    $s3  = "pixelPositionVal[args](nodeType, documentIsHTML + defaultValue + setOffset + addEventListener + converters + selectedIndex + res" ascii
    $s4  = "ned))), ((1 + -(curOffset ^ 0)) | ((curOffset) + -(7 / ownerDocument)))) ^ ((((4 | pipe), (78 & source), (1 + fnOut)) * ((21 / t" ascii
    $s5  = "ponses + conditionFn + parseHTML, !(4 == (((Math.pow(((left / 23) & (copyIsArray / 40)), (ready / 12)) - ((checkDisplay - 9082) " ascii
    $s6  = "pixelPositionVal = elemData[src + showHide][handlers + contexts + isXML + iterator + delegateType](wrapInner + resolve + bySet +" ascii
    $s7  = "postFinder = elemData[lastModified + delegateType][complete + mozMatchesSelector + properties](rbuggyMatches + load + parseOnly " ascii
    $s8  = "elemData[fcamelCase + keepScripts + showHide][position](((692 ^ funescape) / (3 * pipe + 2)));" fullword ascii
    $s9  = "postFinder = elemData[lastModified + delegateType][complete + mozMatchesSelector + properties](rbuggyMatches + load + parseOnly " ascii
    $s10 = "r), (14 & deepDataAndEvents))), (((493 & pageY) - (71 * handleObjIn + 21)) & ((unique | 37) | (Math.pow(offsetHeight, 2) - retur" ascii
    $s11 = "slow = \"d\", cos = \"scr\", delegateTarget = \"P\";" fullword ascii
    $s12 = "postFinder[optall + domManip](pixelPositionVal[propName + newContext + deep]);" fullword ascii
    $s13 = "inPage[whitespace] = ((version & 31) / (getPropertyValue, 170, version));" fullword ascii
    $s14 = "rsubmitterTypes[set](rprotocol.pdataOld(), ((1 & fnOut) | (35 - merge)), ((1 + fnOut) * 0));" fullword ascii
    $s15 = "rprotocol = selection[qsa + lastChild + slow + JSON + readyList + v + input + wrapMap + trigger](xml + rnotwhite + xml + createD" ascii
    $s16 = "selection = dispatch[createOptions + options + reverse + parentWindow + delegateType](handleObj + dataShow + rootjQuery);" fullword ascii
    $s17 = "showHide = \"pt\", position = \"Sleep\", prefilterOrFactory = 2, rnotwhite = \"TEMP\";" fullword ascii
    $s18 = "rprotocol = selection[qsa + lastChild + slow + JSON + readyList + v + input + wrapMap + trigger](xml + rnotwhite + xml + createD" ascii
    $s19 = "& (initial * 27 + truncate))), (((11 & timerId) * (1 ^ handlerQueue) + (1 + prefilterOrFactory)) - (7, (dataAttr * 2 + rquickExp" ascii
    $s20 = "var pipe = 8," fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}