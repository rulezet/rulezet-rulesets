rule sig_20160309_379f8a6415b6aab012da7dc0cec238c1 {
  meta:
    description = "datamaliciousorder - file 20160309_379f8a6415b6aab012da7dc0cec238c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fb8878de2154331496dcc956e875e6f8762ef7177488495d71c990cc889cc08"

  strings:
    $s1  = "border = nType[processData + triggered + rsubmittable + msg + prefix + nextUntil](split + ready) + ajax + off + ifModified + uni" ascii
    $s2  = "border = nType[processData + triggered + rsubmittable + msg + prefix + nextUntil](split + ready) + ajax + off + ifModified + uni" ascii
    $s3  = "childNodes[documentIsHTML](file + err, adown + newUnmatched + random + offsetHeight + operator + overflowY + mimeType + onabort " ascii
    $s4  = "step[ajaxConvert + mappedTypes][bp + aup](((getWindow, 231, createInputPseudo, 12345) ^ (module - 1910)));" fullword ascii
    $s5  = "childNodes = step[pseudos + rmouseEvent + offset][owner + rmouseEvent + bind + timers + _ + rescape](createComment + targets + h" ascii
    $s6  = "childNodes = step[pseudos + rmouseEvent + offset][owner + rmouseEvent + bind + timers + _ + rescape](createComment + targets + h" ascii
    $s7  = " 31, structure))), ((23 ^ rootjQuery) / (8 | pageYOffset)) * 2 * (factory / 3)) | (((xhrSupported - 41) | (callback ^ 1)) + -((s" ascii
    $s8  = "childNodes[documentIsHTML](file + err, adown + newUnmatched + random + offsetHeight + operator + overflowY + mimeType + onabort " ascii
    $s9  = "selector[rquery + PI] = ((events, 27, setAttribute) - (10 ^ createHTMLDocument));" fullword ascii
    $s10 = "unit = \".scr\";" fullword ascii
    $s11 = "nType = JSON[owner + handleObj + combinator](pseudos + preventDefault + letterSpacing);" fullword ascii
    $s12 = "undelegate[rprotocol + bind]();" fullword ascii
    $s13 = "step = (((1575 / parseXML) & (50 + find)), ((Math.pow((91 / setAttribute), (2 & mouseenter)) - (2 * jsonpCallback)), this));" fullword ascii
    $s14 = "rnative = step[ajaxConvert + mappedTypes][tr + transport + marginRight](detach + wrapInner + rneedsContext);" fullword ascii
    $s15 = "operator = \"o/\", args = \"type\", triggered = \"Enviro\", msg = \"tSt\", aup = \"eep\", createInputPseudo = 76;" fullword ascii
    $s16 = "JSON = step[specialEasing + setMatcher];" fullword ascii
    $s17 = "rnative[lastModified + docElem + replaceChild + types](border, ((72 / jsonProp) + 0));" fullword ascii
    $s18 = "allTypes = childNodes[select + remove + blur + rcssNum];" fullword ascii
    $s19 = "ready = \"P%/\";" fullword ascii
    $s20 = "adown = \"http\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}