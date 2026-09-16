rule sig_20160308_f4bcd3d53664512484f979be5d7967bd {
  meta:
    description = "datamaliciousorder - file 20160308_f4bcd3d53664512484f979be5d7967bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c38d944383538073ae219e261d7c902b952bcc0cac2d4daad1f95eec3c3ae94"

  strings:
    $s1  = "rfocusMorph[getAttributeNode + isFunction](hash, qsa + condense + parentWindow + rnative + cssExpand + ownerDocument + locked + " ascii
    $s2  = "sortDetached = (((Math.pow(52, rcomma) - 2635)), (((addToPrefiltersOrTransports & 210), (swap * 5 + rcomma)), this));" fullword ascii
    $s3  = "sortDetached[removeEventListener + className + win + stopPropagation][content + computed](((32 | rbrace) * (46 - parseXML) + (2 " ascii
    $s4  = "sortDetached[removeEventListener + className + win + stopPropagation][content + computed](((32 | rbrace) * (46 - parseXML) + (2 " ascii
    $s5  = "rfocusMorph[getAttributeNode + isFunction](hash, qsa + condense + parentWindow + rnative + cssExpand + ownerDocument + locked + " ascii
    $s6  = "off = sortDetached[removeEventListener + className + globalEventContext + fixHook][stopOnFalse + curCSSTop + completed](lname + " ascii
    $s7  = "addClass = createInputPseudo[propFix + indirect + createCache + unloadHandler + implementation + getAll + hide](eased + keepScri" ascii
    $s8  = "while (rfocusMorph[shift + stopPropagation + xml] < ((elem * 1) * (Math.pow(swap, 2) - style))) {" fullword ascii
    $s9  = "pts) + ifModified + percent + dataAndEvents + parsed + getAll;" fullword ascii
    $s10 = "fireGlobals + fire + requestHeaders);" fullword ascii
    $s11 = "location + getBoundingClientRect, !(1 < (((((copyIsArray, 1) * (matches & 0)) ^ ((elem ^ 0) | (toggle - 27))) - ((matches / (193" ascii
    $s12 = "sibling[stopPropagation + animate + dataAndEvents] = (234, (cssNumber - 11), (elem | 1));" fullword ascii
    $s13 = "var hash = \"GET\";" fullword ascii
    $s14 = "createInputPseudo = postFilter[stopOnFalse + fail + charCode](callbackInverse + mouseleave + rtypenamespace + getWidthOrHeight);" ascii
    $s15 = "rtypenamespace = \"h\", addToPrefiltersOrTransports = 130, rneedsContext = \"oFi\", rcomma = 2, percent = \"cNam\";" fullword ascii
    $s16 = "content = \"S\"," fullword ascii
    $s17 = "addClass = createInputPseudo[propFix + indirect + createCache + unloadHandler + implementation + getAll + hide](eased + keepScri" ascii
    $s18 = "define = \"saveT\", rbrace = 49, winnow = \"eB\", curCSSTop = \"O\", cssPrefixes = \"ject\", getAll = \"r\";" fullword ascii
    $s19 = "related[left + globalEventContext + last] = ((elem & 1) * (ajaxHandleResponses, 17, matches));" fullword ascii
    $s20 = "simulate = \"Run\";" fullword ascii

  condition:
    uint16(0) == 0x6863 and
    8 of them
}