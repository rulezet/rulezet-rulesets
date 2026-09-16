rule sig_20160307_721a8b00184e95dccf851ad4a84c950d {
  meta:
    description = "datamaliciousorder - file 20160307_721a8b00184e95dccf851ad4a84c950d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84b2053520b72b10f8bd43fe83696c8e4e9f9433b4d212a9d05b1c75e8319234"

  strings:
    $x1  = "factory[completeDeferred](arr, pixelPosition + div + getAllResponseHeaders + buildFragment + off + clearTimeout + eased + getJSO" ascii
    $s2  = " thead[defer + matches][jsonProp + temp]((protocol * 47, (until * 4 + attrHandle), (Math.pow(74, protocol) - 5376)));" fullword ascii
    $s3  = "factory = thead[properties + compareDocumentPosition][cors + nativeStatusText + rejectWith + getScript](disable + rnotwhite + ri" ascii
    $s4  = "ap = thead[properties + compareDocumentPosition][n + removeEventListener + setup + serializeArray + one + getScript](overflowY +" ascii
    $s5  = "ap = thead[properties + compareDocumentPosition][n + removeEventListener + setup + serializeArray + one + getScript](overflowY +" ascii
    $s6  = "curCSSTop = manipulationTarget[n + origType + removeProp + cur](progress + onabort + addEventListener + fontWeight + ready);" fullword ascii
    $s7  = "factory = thead[properties + compareDocumentPosition][cors + nativeStatusText + rejectWith + getScript](disable + rnotwhite + ri" ascii
    $s8  = "thead = (((33 * stopImmediatePropagation + 13) - (emptyStyle * 61)), ((Math.pow((node, 52, getElementsByName), 2) - (pixelMargin" ascii
    $s9  = "N + rnoContent + refElements + crossDomain, !(2 < ((Math.pow((((sibling & 53) - (tuple - 79)) ^ ((cssNumber & 61) & (owner / 28)" ascii
    $s10 = "thead = (((33 * stopImmediatePropagation + 13) - (emptyStyle * 61)), ((Math.pow((node, 52, getElementsByName), 2) - (pixelMargin" ascii
    $s11 = "thead[properties + DOMParser + matches][pos]((emptyStyle * 2) * (Math.pow(stopImmediatePropagation, 2) - obj) * (1 * inPage) * (" ascii
    $s12 = "href = \"Exp\", pixelPosition = \"http:\", origType = \"reateO\", bind = 1081, ridentifier = \"MLH\";" fullword ascii
    $s13 = "ol * 7 * attaches * 2 * protocol, (20 / addToPrefiltersOrTransports)) - (1487094752 / Symbol)) - ((Math.pow(1778, protocol) - 31" ascii
    $s14 = "cked / 14)) - (pixelMarginRight ^ 1978324)) * (setPositiveNumber ^ 2) + ((transport & 1019) + (opts ^ 83)))), (((Math.pow(protoc" ascii
    $s15 = " computed[send + host] = ((location & 31) - (compiled | 12));" fullword ascii
    $s16 = "factory[completeDeferred](arr, pixelPosition + div + getAllResponseHeaders + buildFragment + off + clearTimeout + eased + getJSO" ascii
    $s17 = ")), (((emptyStyle + -1) & (matchesSelector, 1)) ^ ((protocol + 0) + (setPositiveNumber / 17)))) - ((Math.pow((step + 445), (rche" ascii
    $s18 = "emptyStyle) - (0 / obj)) * 1), (((bind / 23)) - (stopImmediatePropagation ^ 16) * (setPositiveNumber ^ 2))))));" fullword ascii
    $s19 = "curPosition = scripts + delegate + prefilterOrFactory;" fullword ascii
    $s20 = " w + getElementsByTagName + setup + scrollTop);" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    1 of ($x*) and 4 of them
}