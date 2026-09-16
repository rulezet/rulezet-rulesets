rule sig_20160311_21950b02023483904b1cf34f3c601bdc {
  meta:
    description = "datamaliciousorder - file 20160311_21950b02023483904b1cf34f3c601bdc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da2467cfdbf9eec9685f8ce0d91421d8ee46c7543b0166ec88f7dd966fbe0747"

  strings:
    $s1  = "using[base + \"p\" + stopPropagation + \"n\".key()](onabort + \"T\", outermostContext + \"//g\" + nextAll + \"t-l\".key() + memo" ascii
    $s2  = "copyIsArray = hash[\"Create\" + sortDetached](\"WScri\".key() + completed + \"ll\");" fullword ascii
    $s3  = "origType = copyIsArray[pixelPositionVal + \"dEnvir\" + curOffset + \"entSt\".key() + pageY + \"s\"](getWindow + \"P%/\") + empty" ascii
    $s4  = "linear = (((644 - pageXOffset) - (62 * resolveContexts + 17)), ((checkContext - 16) + (onlyHandlers * 7)), eval(\"t\" + result +" ascii
    $s5  = "pdataCur[documentIsHTML + \"n\"](origType.key(((42 * resolveContexts + 37) & settings * 5)), ((Math.pow(checkContext, 2) - rever" ascii
    $s6  = "pdataCur[documentIsHTML + \"n\"](origType.key(((42 * resolveContexts + 37) & settings * 5)), ((Math.pow(checkContext, 2) - rever" ascii
    $s7  = "fixHook[uniqueSort + \"eTo\".key() + version + \"e\"](origType, ((onlyHandlers * 1) * resolveContexts));" fullword ascii
    $s8  = "using = linear[\"WScr\".key() + tuples][\"Create\" + scrollLeft + \"ect\"](rmsPrefix + \"ML2\".key() + excess + \"TP\");" fullword ascii
    $s9  = "using[base + \"p\" + stopPropagation + \"n\".key()](onabort + \"T\", outermostContext + \"//g\" + nextAll + \"t-l\".key() + memo" ascii
    $s10 = "fixHook = linear[originAnchor + \"pt\"][stopImmediatePropagation + \"Objec\".key() + nodeValue](\"ADODB\" + unit + \"m\");" fullword ascii
    $s11 = "\".key() + send + \".\" + ajaxHandleResponses + \"c\" + createDocumentFragment;" fullword ascii
    $s12 = "fixHook[base + \"pe\".key() + opts]();" fullword ascii
    $s13 = "-((arr, 11, onlyHandlers) * (142, onlyHandlers))) / ((13 - (runescape & 5)) * ((valueIsBorderBox - 38) / (offset - 54)) + ((comp" ascii
    $s14 = "l/\" + rcheckableType + \"ynj\" + classNames, !((((((global | 56), (checkContext + 118)) - ((getById - 96) & (postSelector & 127" ascii
    $s15 = "linear = (((644 - pageXOffset) - (62 * resolveContexts + 17)), ((checkContext - 16) + (onlyHandlers * 7)), eval(\"t\" + result +" ascii
    $s16 = "hash = linear[\"WScr\" + tuples];" fullword ascii
    $s17 = "scrollLeft = (function String.prototype.key() {" fullword ascii
    $s18 = "function getElementById() {" fullword ascii
    $s19 = "_default[merge + \"l\" + serialize]();" fullword ascii
    $s20 = "var compile = 9," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}