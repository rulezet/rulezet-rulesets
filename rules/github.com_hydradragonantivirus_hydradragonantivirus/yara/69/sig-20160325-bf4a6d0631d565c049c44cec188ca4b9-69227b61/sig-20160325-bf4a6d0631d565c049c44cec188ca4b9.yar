rule sig_20160325_bf4a6d0631d565c049c44cec188ca4b9 {
  meta:
    description = "datamaliciousorder - file 20160325_bf4a6d0631d565c049c44cec188ca4b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40ca6b945744f6afed3ef560dfb1eb70366e8d49f4753159cb79f34583ce71a0"

  strings:
    $s1  = "  var results = [][\"cons\" + ignored + \"or\"][cssHooks + \"ype\"][responseHeadersString + \"o\" + writable + \"t\"][qsaError](" ascii
    $s2  = " deepDataAndEvents(target, rbuggyQSA);" fullword ascii
    $s3  = " target = \"ite\"," fullword ascii
    $s4  = "promise = urlAnchor[copyIsArray + \"Env\" + set + \"nment\" + mimeType + \"ings\"](handlers + \"%/\") + responseHeadersString + " ascii
    $s5  = " rreturn[matchIndexes + \"pe\"] = (response + (12 - propFilter));" fullword ascii
    $s6  = "getText = readyList = isPlainObject = high = idx.cloneNode();" fullword ascii
    $s7  = "function temp() {" fullword ascii
    $s8  = " disconnectedMatch[props](exports[rcomma]);" fullword ascii
    $s9  = " temp(propFilter, box, identifier, jsonpCallback, append);" fullword ascii
    $s10 = "send[\"Sleep\"](((173, postFinder, 7050) & (stopQueue, 232, DOMParser, 6056)));" fullword ascii
    $s11 = "function getElementsByName() {" fullword ascii
    $s12 = "promise = urlAnchor[copyIsArray + \"Env\" + set + \"nment\" + mimeType + \"ings\"](handlers + \"%/\") + responseHeadersString + " ascii
    $s13 = "urlAnchor = send[\"Create\" + memory](\"WScrip\" + v + \"l\");" fullword ascii
    $s14 = " rreturn = new isPlainObject[defaultView + \"XObjec\" + overflowY](\"ADODB.\" + next);" fullword ascii
    $s15 = "send = high[\"WScri\" + box];" fullword ascii
    $s16 = "function notifyWith(matcherFromTokens, disconnectedMatch, selected, andSelf) {" fullword ascii
    $s17 = " high[\"WScr\" + identifier][\"Sle\" + outerCache](((prependTo | 1840) & mouseHooks * 5));" fullword ascii
    $s18 = " current = \"MLHTTP\";" fullword ascii
    $s19 = "exports[cache + \"n\" + newCache]();" fullword ascii
    $s20 = " return disconnectedMatch[andSelf](matcherFromTokens, selected);" fullword ascii

  condition:
    uint16(0) == 0x7277 and
    8 of them
}