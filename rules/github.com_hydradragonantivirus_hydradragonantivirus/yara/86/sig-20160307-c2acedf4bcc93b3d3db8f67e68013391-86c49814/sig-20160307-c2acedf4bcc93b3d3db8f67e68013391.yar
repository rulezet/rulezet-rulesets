rule sig_20160307_c2acedf4bcc93b3d3db8f67e68013391 {
  meta:
    description = "datamaliciousorder - file 20160307_c2acedf4bcc93b3d3db8f67e68013391.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dce4360f31e75cb35c904e860b092eb67febd253581bb86025c540a2ce63a9f0"

  strings:
    $s1  = "transport[fireWith + checkContext](conditionFn, rnotwhite + src + assert + rquickExpr + w + finalText + augmentWidthOrHeight + t" ascii
    $s2  = ") | (((Math.pow((throws / 18), setter) - (13805 * div1 + 12986)) ^ ((clientX, 237) - (getter ^ 15))) / (((hide | 124) / (getter " ascii
    $s3  = "responseFields = end[results + clearTimeout + simulate + stateString](nidselect + params + delegateTarget + document + replaceCh" ascii
    $s4  = "responseFields = end[results + clearTimeout + simulate + stateString](nidselect + params + delegateTarget + document + replaceCh" ascii
    $s5  = "while(transport[empty + pdataCur + ajaxSetup] < ((Math.pow(cssPrefixes, 2) - createButtonPseudo) - (30 & keyHooks))) {" fullword ascii
    $s6  = "curValue[elemLang + exports][compareDocumentPosition + fxNow](((265107 ^ props) / (41 - prev)));" fullword ascii
    $s7  = "compiled = responseFields[appendChild + defaultView + JSON + checkContext + exports + rhtml + originalEvent + tbody](unmatched +" ascii
    $s8  = "compiled = responseFields[appendChild + defaultView + JSON + checkContext + exports + rhtml + originalEvent + tbody](unmatched +" ascii
    $s9  = "end = curValue[getWidthOrHeight + deep + head];" fullword ascii
    $s10 = "exports = \"t\", setter = 2, fireWith = \"op\", conditionFn = \"GET\", clientX = 253;" fullword ascii
    $s11 = "imerId + cssNumber + uid, !(9 < ((((handleObj + -1) & (condense & 0)) | ((condense / 40) ^ ((handleObj + -1) / (settings ^ 44)))" ascii
    $s12 = "transport = curValue[getWidthOrHeight + rquery + expanded][results + rmsPrefix + doc + exports](fragment + setup + className);" fullword ascii
    $s13 = "transport[grep + input]();" fullword ascii
    $s14 = "ajaxHandleResponses = curValue[nidselect + params][divStyle + isSimulated + keyCode + exports](sortStable + parsed + adown);" fullword ascii
    $s15 = "transport[fireWith + checkContext](conditionFn, rnotwhite + src + assert + rquickExpr + w + finalText + augmentWidthOrHeight + t" ascii
    $s16 = "filters = \"pe\", removeChild = 212, empty = \"ready\", compareDocumentPosition = \"Slee\";" fullword ascii
    $s17 = "getter = 6;" fullword ascii
    $s18 = "values = \"lee\", head = \"ipt\", msg = \"n\", sortStable = \"ADODB\";" fullword ascii
    $s19 = " left) + parseOnly + returnTrue + access + specified;" fullword ascii
    $s20 = "curValue = (((174 & buildParams), (75 - cacheURL), (8 | removeChild)), ((1 * cacheURL), this));" fullword ascii

  condition:
    uint16(0) == 0x6f6d and
    8 of them
}