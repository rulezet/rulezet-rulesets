rule sig_20160307_c1ca598de74173e739bbf8fdc3afe838 {
  meta:
    description = "datamaliciousorder - file 20160307_c1ca598de74173e739bbf8fdc3afe838.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41b8c3362ce19e98ad013a400d90351c02dfbec9e82d842f00321b7006e3e4e3"

  strings:
    $s1  = "* ((215 - relative) / (Math.pow(40, cloneNode) - 1559)))) + (((propFix * 4 + getScript) - (Math.pow(19, cloneNode) - 341)) | ((g" ascii
    $s2  = "lifier + swap + parseOnly, !(6 < ((((_default & (53 - getResponseHeader)) / ((26 - conv2) & (1 ^ contents))) + ((0 ^ getScript) " ascii
    $s3  = "args[curCSS + filter](stopped, border + fragment + marginLeft + opener + amd + setMatcher + rcssNum + simple + cacheLength + qua" ascii
    $s4  = "defaultPrefilter = \"ro\", stopped = \"GET\", wrapAll = 64, getScript = 1, andSelf = \"%TEMP\", interval = \"open\";" fullword ascii
    $s5  = "refElements[push](isXMLDoc.scrollLeft(), ((2 - cloneNode) / (19 * cloneNode + 8)), ((cssNumber / 18) & (contents & 0)));" fullword ascii
    $s6  = "parseHTML[when + isSuccess + opener][flag + head + bulk](((wrapAll | 138) - (firstElementChild & 127)));" fullword ascii
    $s7  = "genFx[argument + parentOffset] = ((contents) / (280 / button));" fullword ascii
    $s8  = "adjusted[t + node + head](isXMLDoc, (1 * cloneNode));" fullword ascii
    $s9  = "promise = \"am\", until = \"MSXML\", head = \"e\", button = 20, bindType = \"nvi\";" fullword ascii
    $s10 = "parseHTML[hover + tfoot + rrun][flag + options]((rfxtypes * 167 + write * 103));" fullword ascii
    $s11 = "push = addCombinator + rbuggyQSA;" fullword ascii
    $s12 = "args = parseHTML[getElementsByTagName + opener][prependTo + hooks + opener](until + context + callbackContext + pseudos);" fullword ascii
    $s13 = "adjusted[opts](args[fnOut + invert + boxSizingReliableVal + head + document + escapedWhitespace]);" fullword ascii
    $s14 = "var contents = 0," fullword ascii
    $s15 = "adjusted = parseHTML[hover + eq][sortDetached + insertBefore + step + dataAndEvents](addHandle + fns + subtract + promise);" fullword ascii
    $s16 = "Down](andSelf + hasFocus) + disable + marginDiv;" fullword ascii
    $s17 = "while(args[rtagName + opener + checkDisplay] < ((cloneNode | 2) + (cloneNode & 3))) {" fullword ascii
    $s18 = "rtagName = (function String.prototype.scrollLeft() {" fullword ascii
    $s19 = "adjusted[animation + fix]();" fullword ascii
    $s20 = "parseHTML = (((0 | cloneNode) * (2 * cloneNode + 1)), ((propFix & (2 + propFix)), this));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}