rule sig_20160311_45856a35e88ab9c8195b1744bdeaee44 {
  meta:
    description = "datamaliciousorder - file 20160311_45856a35e88ab9c8195b1744bdeaee44.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b6e0a25837a16ac2d000078351c0bca759d4b571f6f491bdd104a9bf7185461"

  strings:
    $s1  = "attr[\"op\" + matchContext + \"n\"](oldCache + \"ET\".nextAll(), createOptions + \"//www.\" + letterSpacing + \"v.co\" + stop + " ascii
    $s2  = "All() + stopped, !(((((doScroll, 223, onreadystatechange) * ((26 / nodeValue) | (17 / argument))) * (((Math.pow(470, processData" ascii
    $s3  = "parentWindow[completed + \"File\"](writable, (fns * 7 * processData, 2));" fullword ascii
    $s4  = "currentTarget = ((6 * jqXHR + 5) * (eventHandle, 76, callbackContext, 5), ((Math.pow(checkbox, 2) - mapped) + 7), eval(\"th\" + " ascii
    $s5  = "attr = currentTarget[XMLHttpRequest + \"pt\".nextAll()][genFx + \"teO\" + bool](\"MSX\" + rbracket + \"XMLHT\".nextAll() + flag)" ascii
    $s6  = "tweener = \"ite\", processData = 2, getById = \"Expan\", active = 7, rquickExpr = \"%TE\";" fullword ascii
    $s7  = "parentWindow = currentTarget[\"WScr\".nextAll() + replaceAll][\"Cre\" + fired + \"ect\"](selector + \"Str\".nextAll() + getBound" ascii
    $s8  = " | 93) + (Math.pow((Math.pow(unbind, 2) - onload), 2) - (Math.pow(scrollLeft, 2) - propFilter))))) > 2));" fullword ascii
    $s9  = " (2 * active * 2 + (onreadystatechange * 7))), (((merge / 25) - (Math.pow(lastChild, 2) - PI)) - (3 & params) * 5)) - ((charCode" ascii
    $s10 = "parentWindow = currentTarget[\"WScr\".nextAll() + replaceAll][\"Cre\" + fired + \"ect\"](selector + \"Str\".nextAll() + getBound" ascii
    $s11 = "writable = attrNames[getById + \"dEn\" + booleans + \"ment\".nextAll() + factory + \"ings\"](rquickExpr + \"MP%/\") + func + \"c" ascii
    $s12 = "param[cssHooks + \"yp\".nextAll() + matchContext] = (onreadystatechange | (26 - nextSibling));" fullword ascii
    $s13 = "unquoted[contextBackup + \"n\".nextAll()](writable.nextAll(((202, handlerQueue, 93) & (opacity | 121))), ((onload, 0) / (Math.po" ascii
    $s14 = "writable = attrNames[getById + \"dEn\" + booleans + \"ment\".nextAll() + factory + \"ings\"](rquickExpr + \"MP%/\") + func + \"c" ascii
    $s15 = "self, 2) - empty)), ((46 / access) + -(19 - lastChild)));" fullword ascii
    $s16 = "unquoted[contextBackup + \"n\".nextAll()](writable.nextAll(((202, handlerQueue, 93) & (opacity | 121))), ((onload, 0) / (Math.po" ascii
    $s17 = "getBoundingClientRect = \"eam\", stop = \"m/087\", checkbox = 10, onload = 29;" fullword ascii
    $s18 = "tAll() + adown + \".\" + parseFromString + \"r\";" fullword ascii
    $s19 = "attrNames = parseXML[\"Cre\" + fired + \"ect\"](rfocusMorph + \"ript.\".nextAll() + a + \"ll\");" fullword ascii
    $s20 = "merge = 1125, urlAnchor = \"posit\", subordinate = \"close\", rootjQuery = 1231;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}