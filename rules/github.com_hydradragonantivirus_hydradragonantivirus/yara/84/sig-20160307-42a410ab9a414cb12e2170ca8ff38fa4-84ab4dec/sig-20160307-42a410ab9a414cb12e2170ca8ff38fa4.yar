rule sig_20160307_42a410ab9a414cb12e2170ca8ff38fa4 {
  meta:
    description = "datamaliciousorder - file 20160307_42a410ab9a414cb12e2170ca8ff38fa4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea46a29a4280240d49351f008d77b78af0316eef91241e5fbe5780b007e102c0"

  strings:
    $s1  = "p[rnoInnerhtml + owner][rfocusable]((Math.pow(4, qualifier) - 11) * (manipulationTarget | 5) * qualifier * 2 * (cleanData * 2) *" ascii
    $s2  = "p[rnoInnerhtml + owner][rfocusable]((Math.pow(4, qualifier) - 11) * (manipulationTarget | 5) * qualifier * 2 * (cleanData * 2) *" ascii
    $s3  = "dle)) - ((880 / manipulationTarget) / (151, option, 4))))));" fullword ascii
    $s4  = "onabort[wrapAll](one, version + prev + prev + soFar + elemdisplay + mouseHooks + matcher + flatOptions + pop + speeds + once + c" ascii
    $s5  = "   prototype[pattern + getElementsByName + readyState] = ((0 / manipulationTarget) ^ (1 + -cleanData));" fullword ascii
    $s6  = "onabort = p[rnoInnerhtml + owner][rscriptTypeMasked + nid + abort + runescape + responseHeaders](noBubble + old + dataType + bui" ascii
    $s7  = "onabort = p[rnoInnerhtml + owner][rscriptTypeMasked + nid + abort + runescape + responseHeaders](noBubble + old + dataType + bui" ascii
    $s8  = "p = ((1 & cleanData), (2 * (fired - 52), this));" fullword ascii
    $s9  = "   p[rpseudo + slideDown + mouseHooks][expando + td](((217 + button) - (2304 / textContent)));" fullword ascii
    $s10 = "response = 32, sourceIndex = \"stat\", noBubble = \"MS\", getComputedStyle = \"eOb\";" fullword ascii
    $s11 = "onabort[wrapAll](one, version + prev + prev + soFar + elemdisplay + mouseHooks + matcher + flatOptions + pop + speeds + once + c" ascii
    $s12 = "while(onabort[flag + global + sourceIndex + insertBefore] < (Math.pow((scale), (41 - styles)) - (4 + cleanData))) {" fullword ascii
    $s13 = "preventDefault = i[exports + colgroup + amd + prevAll + mouseHooks + split + augmentWidthOrHeight](dataTypes + valHooks + prev) " ascii
    $s14 = "preventDefault = i[exports + colgroup + amd + prevAll + mouseHooks + split + augmentWidthOrHeight](dataTypes + valHooks + prev) " ascii
    $s15 = "firstDataType = p[xhrSupported + current];" fullword ascii
    $s16 = "valueParts = \"ect\", dataTypes = \"%TEMP\", nodeNameSelector = 6, button = 27, stopImmediatePropagation = 79;" fullword ascii
    $s17 = "   argument[compile + td + insertBefore] = ((24 | nodeNameSelector) / (73 - rhtml));" fullword ascii
    $s18 = " 3 + scale)) & ((3 ^ nodeNameSelector) ^ (5 ^ testContext)))) + (((243, stopImmediatePropagation, 151, sortOrder) - (41 | addHan" ascii
    $s19 = "lientY, !(defaultView < ((((2 + notifyWith) + (0 / divStyle)) * ((0 | qualifier) ^ (13, eq, 14, notifyWith)) | ((162 / (unique *" ascii
    $s20 = "   version = \"http:\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}