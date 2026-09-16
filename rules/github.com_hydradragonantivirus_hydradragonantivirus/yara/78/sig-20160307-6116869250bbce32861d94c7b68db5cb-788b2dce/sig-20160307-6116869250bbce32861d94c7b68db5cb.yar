rule sig_20160307_6116869250bbce32861d94c7b68db5cb {
  meta:
    description = "datamaliciousorder - file 20160307_6116869250bbce32861d94c7b68db5cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7e6537ced6f48bda11683b951364dd4bdc9f61999437a21bc730220384f198a"

  strings:
    $x1  = "xhr[animate + flatOptions + duplicates + rscriptTypeMasked](risSimple + preexisting, fx + createHTMLDocument + complete + cacheU" ascii
    $s2  = "xhr = matchContext[matcherOut + urlAnchor][tween + processData + on + border](parse + content + binary + sort);" fullword ascii
    $s3  = " - ((restoreScript, 0) | (node & 10))) & (((code / 32), (invert & 255), (domManip - 2)) * (getResponseHeader / 3))) * ((((preven" ascii
    $s4  = "before = unloadHandler[getWidthOrHeight + hasContent + readyState + merge + htmlPrefilter](end + andSelf + opacity) + jsonp + im" ascii
    $s5  = "before = unloadHandler[getWidthOrHeight + hasContent + readyState + merge + htmlPrefilter](end + andSelf + opacity) + jsonp + im" ascii
    $s6  = "42, hookFn, 127)), ((password & 56) - (container & 63))))));" fullword ascii
    $s7  = "RL + postFinder + handlerQueue + push + clientX + identifier + token + resolveValues, !(8 < ((((rhtml / 37) - (rquickExpr & 47))" ascii
    $s8  = "5)) & (((whitespace, 252, height) | (2 & domManip)) & ((33 / rhash) + (0 | height)))) * ((((Math.pow(37, height) - 1315) / (rfxt" ascii
    $s9  = "unloadHandler = reset[prevObject + manipulationTarget + options + tweeners](matcherOut + oldCallbacks + addEventListener);" fullword ascii
    $s10 = "extend = matchContext[matcherOut + urlAnchor][rheaders + parsed + optgroup](after + stopOnFalse + computed);" fullword ascii
    $s11 = "extend[responseFields + newSelector + requestHeaders + duplicates](before, ((87, hasCompare, 54) - (replaceWith ^ 4)));" fullword ascii
    $s12 = "processData = \"ateO\", password = 50, replaceAll = \"ready\", merge = \"mentS\", duplicates = \"e\", htmlPrefilter = \"trings\"" ascii
    $s13 = "xhr[animate + flatOptions + duplicates + rscriptTypeMasked](risSimple + preexisting, fx + createHTMLDocument + complete + cacheU" ascii
    $s14 = "ult / 41)) ^ ((preventDefault ^ 1) ^ (random - 53)))) * (((percent - (12, assert, 203, step)), ((47 - parseHTML) - 2 * height * " ascii
    $s15 = "hasData = 156, options = \"ateOb\", optgroup = \"t\", implicitRelative = \".scr\", node = 14;" fullword ascii
    $s16 = "matchContext[rcomma + class2type][dataAndEvents](((177 - querySelectorAll), 2 * height * 7 * height * 3, domManip * 3 * domManip" ascii
    $s17 = "matchContext[rcomma + class2type][dataAndEvents](((177 - querySelectorAll), 2 * height * 7 * height * 3, domManip * 3 * domManip" ascii
    $s18 = "content = \".X\";" fullword ascii
    $s19 = "extend[w + isNumeric + marginRight](xhr[preDispatch + rheader + duplicates + rtypenamespace]);" fullword ascii
    $s20 = "getWidthOrHeight = \"Exp\", urlAnchor = \"ipt\", risSimple = (function Object.prototype.handleObj() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}