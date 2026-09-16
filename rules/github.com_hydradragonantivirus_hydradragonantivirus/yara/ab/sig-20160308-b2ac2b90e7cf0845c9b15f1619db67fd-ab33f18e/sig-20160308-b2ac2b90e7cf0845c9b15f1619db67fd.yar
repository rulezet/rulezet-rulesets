rule sig_20160308_b2ac2b90e7cf0845c9b15f1619db67fd {
  meta:
    description = "datamaliciousorder - file 20160308_b2ac2b90e7cf0845c9b15f1619db67fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0f135f9f1a412231dc0f5307092e21736dd846344dfca79a3929265f5ea9240"

  strings:
    $s1  = "eased[handleObjIn + overrideMimeType + contextBackup](qsa, selectors + after + compilerCache + curOffset + getClientRects + conv" ascii
    $s2  = "e = ajaxSetup[ajax + document + namespace + compilerCache + emptyGet + method + removeAttribute + check + runescape](tuples + tr" ascii
    $s3  = "eased[handleObjIn + overrideMimeType + contextBackup](qsa, selectors + after + compilerCache + curOffset + getClientRects + conv" ascii
    $s4  = "urLeft)))) * ((((3 | checkNonElements) - (64 - chainable)), ((16 | ontype) ^ (34 * mappedTypes + 27)), ((expand & 222), (getter " ascii
    $s5  = "e = ajaxSetup[ajax + document + namespace + compilerCache + emptyGet + method + removeAttribute + check + runescape](tuples + tr" ascii
    $s6  = "while(eased[state + focus + set + matchExpr + removeData] < ((Math.pow(65, extend) - 4137) / (Math.pow(whitespace, 2) - pixelMar" ascii
    $s7  = "while(eased[state + focus + set + matchExpr + removeData] < ((Math.pow(65, extend) - 4137) / (Math.pow(whitespace, 2) - pixelMar" ascii
    $s8  = "iggered + code) + createInputPseudo + exports + tokens + second + nextUntil;" fullword ascii
    $s9  = "origName = toSelector[createDocumentFragment + propFilter][abort + getElementsByName + events + set](rhtml + minWidth + original" ascii
    $s10 = "origName = toSelector[createDocumentFragment + propFilter][abort + getElementsByName + events + set](rhtml + minWidth + original" ascii
    $s11 = "toSelector[nativeStatusText + rcheckableType + propFilter][removeAttribute + step + strAbort](((stopImmediatePropagation | 10247" ascii
    $s12 = "divStyle[isSimulated + wait + serializeArray] = ((1 & isXMLDoc) + -1);" fullword ascii
    $s13 = " + div + colgroup + blur, !(((((originalOptions / 46) - (init / 20)) | ((mappedTypes * (8 | extend)) - ((4 + startTime) + (3 ^ c" ascii
    $s14 = "ajaxSetup = bySet[identifier + anim + msg + parts](empty + container + params);" fullword ascii
    $s15 = "merge = \"Cre\", tokens = \".s\", createInputPseudo = \"rootj\", identifier = \"Create\", expand = 221, matchExpr = \"a\";" fullword ascii
    $s16 = "getter = 223," fullword ascii
    $s17 = "toSelector[nativeStatusText + DOMParser][boxSizingReliable + createTween](((4 ^ always) & 5 * src * 2));" fullword ascii
    $s18 = "toSelector[nativeStatusText + rcheckableType + propFilter][removeAttribute + step + strAbort](((stopImmediatePropagation | 10247" ascii
    $s19 = "toSelector = (((68 + adown) & (50 * extend + 25)), (((cos ^ 5) ^ (isXMLDoc * 2)), this));" fullword ascii
    $s20 = "eased = toSelector[nativeStatusText + DOMParser][merge + a + r20](allTypes + nextAll + setDocument + styles);" fullword ascii

  condition:
    uint16(0) == 0x656d and
    8 of them
}