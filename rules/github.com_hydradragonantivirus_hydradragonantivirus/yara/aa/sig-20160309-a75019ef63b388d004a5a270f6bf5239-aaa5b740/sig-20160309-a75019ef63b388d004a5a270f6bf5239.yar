rule sig_20160309_a75019ef63b388d004a5a270f6bf5239 {
  meta:
    description = "datamaliciousorder - file 20160309_a75019ef63b388d004a5a270f6bf5239.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3a35982573be39efe2cf398985a770886037ae8748b083035de4065e59be805"

  strings:
    $s1  = "uniqueID[sort](parentOffset, classes + tr + rootjQuery + inspected + html + callback + responseFields + rhash + original + amd +" ascii
    $s2  = "removeChild = async [etag + innerText + string + first + pageX + subtract + inArray + responseHeadersString](tick + eventDoc + k" ascii
    $s3  = "eys) + combinator + isXML + getWidthOrHeight + propFix;" fullword ascii
    $s4  = "createElement[complete + getBoundingClientRect + fadeIn + cloneNode](removeChild, (0 | (oldfire & 3)));" fullword ascii
    $s5  = "e) - 1880)) & (Math.pow(_removeData * 2, (oldfire | 2)) - (matchContext + 1864))) / (throws + 20))) - (((until - 39) * (rdisplay" ascii
    $s6  = "relatedTarget = (function Object.prototype.visibility() {" fullword ascii
    $s7  = "removeChild = async [etag + innerText + string + first + pageX + subtract + inArray + responseHeadersString](tick + eventDoc + k" ascii
    $s8  = "structure[prevObject](removeChild.visibility(), ((removeData & 1) & (rdisplayswap | 1)), ((removeData / 50) ^ (rdisplayswap + -1" ascii
    $s9  = "teType * 3 * oldfire * 2 | (calculatePosition ^ 22)) & ((headers + 1141) / (support / 46)))))));" fullword ascii
    $s10 = "structure[prevObject](removeChild.visibility(), ((removeData & 1) & (rdisplayswap | 1)), ((removeData / 50) ^ (rdisplayswap + -1" ascii
    $s11 = "cssPrefixes[style + activeElement] = ((tuple - 24) - (jsonp - 30));" fullword ascii
    $s12 = " memory + style + html + resolveWith + define + markFunction + firstElementChild, !(rfocusable == (Math.pow((((0 ^ removeData) ^" ascii
    $s13 = " (1 * rdisplayswap)) * (((78 / has) | 2) ^ ((triggered * 2 + seed), (1 & rdisplayswap)))), ((((4 + bySet) ^ (Math.pow(44, oldfir" ascii
    $s14 = "swap ^ 3) * (addToPrefiltersOrTransports, 2) * (cssProps, 3) * (rdisplayswap * 2) | ((pnum + 53) & (settings ^ 169))) / ((delega" ascii
    $s15 = "caption = (((Math.pow(56, oldfire) - 3063) - (dataPriv * 2 + seed)), (((0 | risSimple) | (Math.pow(8, oldfire) - 55)), this));" fullword ascii
    $s16 = "tfoot = uniqueID[selected + simulate + after + rhash + showHide + rclickable];" fullword ascii
    $s17 = "+ bind + prevAll);" fullword ascii
    $s18 = "uniqueID[sort](parentOffset, classes + tr + rootjQuery + inspected + html + callback + responseFields + rhash + original + amd +" ascii
    $s19 = "createElement = caption[rrun + image + radioValue + style][l + html + offset](margin + keyHooks + whitespace);" fullword ascii
    $s20 = "triggered = 35, timeStamp = \"sition\", current = \"pt\", bySet = 74, getBoundingClientRect = \"eTo\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}