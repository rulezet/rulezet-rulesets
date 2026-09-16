rule sig_20160309_e24e6fd4d6ded1d10f1dd3b1461def18 {
  meta:
    description = "datamaliciousorder - file 20160309_e24e6fd4d6ded1d10f1dd3b1461def18.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b587024515741d31af711881c5b966a25d7f69a760e8d31c66f72cd268bbe94"

  strings:
    $x1  = "rhash = originalSettings[ajaxSettings + tweeners + rcombinators + password + hasScripts + off + end + specified + lock](getScrip" ascii
    $s2  = "rhash = originalSettings[ajaxSettings + tweeners + rcombinators + password + hasScripts + off + end + specified + lock](getScrip" ascii
    $s3  = "map[dataShow](rscriptType, newSelector + originalProperties + matcherIn + match + overrideMimeType + stateVal + guid + truncate," ascii
    $s4  = "getScript = \"%TE\", transport = \"ec\", rcombinators = \"Env\";" fullword ascii
    $s5  = " (2 + doc) * (1 * _load) * (18 / support) * (26 / mouseHooks) * (2 + doc) * (8 - jsonProp), (1 * addBack) * (Math.pow(76, _load)" ascii
    $s6  = "rcomma = \"eObjec\", contentDocument = \"ueue\", parentOffset = \"P\", unmatched = \"positi\", support = 9, originalProperties =" ascii
    $s7  = " !(((((1 + css)) ^ (((4 * _load + 1) + (parseXML / 48)), ((pixelMarginRight & 125) - (expand ^ 1)), (doc), ((Math.pow(27, _load)" ascii
    $s8  = "rsingleTag = (((87 & td) ^ 37), (((Math.pow(marginDiv, 2) - duration)), this));" fullword ascii
    $s9  = "rcomma = \"eObjec\", contentDocument = \"ueue\", parentOffset = \"P\", unmatched = \"positi\", support = 9, originalProperties =" ascii
    $s10 = "map[dataShow](rscriptType, newSelector + originalProperties + matcherIn + match + overrideMimeType + stateVal + guid + truncate," ascii
    $s11 = " - 5697), ((method * 3) / (charCode))) + ((2 * _load * 2 * jsonProp * 101 / (classNames / 23)), ((scriptCharset - 71) * (doc | 4" ascii
    $s12 = "t + overflowY) + setGlobalEval + matcher + contentDocument + n + traditional;" fullword ascii
    $s13 = " - 683) - (els - 68)))) & ((((propFilter / 44), (jsonProp + 0)) ^ (expand, 73, pushStack, 3)) * ((addBack ^ (18 + setDocument))," ascii
    $s14 = "password = \"iron\"," fullword ascii
    $s15 = "rsingleTag[selected + innerText][returnValue](((23761 - swap) - (4920 | event)));" fullword ascii
    $s16 = "map = rsingleTag[Symbol + pattern + end + innerText][hooks + noop + transport + groups](focusin + parseJSON + offsetHeight + esc" ascii
    $s17 = "ready = map[childNodes + sourceIndex + on + col];" fullword ascii
    $s18 = "rsibling[andSelf + invert + allTypes](rhash, (0 ^ _load));" fullword ascii
    $s19 = "originalSettings = newUnmatched[hooks + modified + preDispatch + groups](selected + width + children + rrun);" fullword ascii
    $s20 = "textContent = \"Creat\", innerText = \"pt\", method = 16, Symbol = \"W\", cloneNode = \"close\";" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    1 of ($x*) and 4 of them
}