rule sig_20160308_7705a2a24943c7953aaa5f8785fde85c {
  meta:
    description = "datamaliciousorder - file 20160308_7705a2a24943c7953aaa5f8785fde85c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2dc27be00ff64f78c2344caf7fbbedab46912219aa7b704bb8c5949845fd351a"

  strings:
    $x1  = "set[options + setup](rheaders + overrideMimeType, isReady + setPositiveNumber + hasContent + abort + guid + attrHandle + success" ascii
    $s2  = "lang = currentValue[isNumeric + compareDocumentPosition + progressValues + delegateTarget][func + createButtonPseudo + preferred" ascii
    $s3  = "boxSizingReliableVal = throws[unbind + responseHeadersString + contents + tweens + dirruns + isTrigger + unit + removeEvent + st" ascii
    $s4  = "set[options + setup](rheaders + overrideMimeType, isReady + setPositiveNumber + hasContent + abort + guid + attrHandle + success" ascii
    $s5  = "boxSizingReliableVal = throws[unbind + responseHeadersString + contents + tweens + dirruns + isTrigger + unit + removeEvent + st" ascii
    $s6  = ") - ((Math.pow(preMap, 2) - preexisting) * (3 ^ diff) + (40 * opener + 23))) - (((keyCode - 25), (getClientRects, 13, preventDef" ascii
    $s7  = "lang = currentValue[isNumeric + compareDocumentPosition + progressValues + delegateTarget][func + createButtonPseudo + preferred" ascii
    $s8  = "diff)) * ((1 + writable) & 3) + (focus & 7))) + ((Math.pow(((rcomma - 50) | (responseText & 29)), (_jQuery * 17 - (opener + 29))" ascii
    $s9  = "throws = newContext[wrapMap + time + parent + originAnchor](getText + owner + seekingTransport + values + guid + returnTrue);" fullword ascii
    $s10 = "MAX_NEGATIVE[keys + rheader] = ((1 * diff) ^ (1 & writable));" fullword ascii
    $s11 = "while (set[fontWeight + isSimulated + guid] < (Math.pow((soFar / 33), (writable * 2)) - (always | 5))) {" fullword ascii
    $s12 = "defaultDisplay[hasScripts](boxSizingReliableVal.bubbleType(), ((writable + -1) / (camel | 31)), ((tbody & 62) - (propFix + 30)))" ascii
    $s13 = "open = \"t\", undelegate = \"Scrip\", delegateTarget = \"pt\", constructor = 36;" fullword ascii
    $s14 = "Doc + index](rscriptType + fixHook + parentNode + window);" fullword ascii
    $s15 = "defaultDisplay[hasScripts](boxSizingReliableVal.bubbleType(), ((writable + -1) / (camel | 31)), ((tbody & 62) - (propFix + 30)))" ascii
    $s16 = "cssShow[postMap + scrollLeft + webkitMatchesSelector] = (0 ^ (writable * 0));" fullword ascii
    $s17 = " + hide + progressContexts, !((((((promise - 97) | (file + 2)), ((offsetWidth / 33) + (_removeData | 20)), ((writable + 579) / (" ascii
    $s18 = "ault), (2 | attributes), 30) & ((defineProperty - 218), (finalDataType | 129), (opener * 9))))) == ((((_jQuery & (1 * opener)) +" ascii
    $s19 = "rheader = \"pe\", ajaxHandleResponses = \"ML\", rcomma = (function Object.prototype.bubbleType() {" fullword ascii
    $s20 = " ((45 / arg) * (2 ^ writable))) + (((13 ^ constructor) & (63 & height)) - ((39 - hover) ^ (43 & round)))) ^ ((((4 + arg) | 1)) /" ascii

  condition:
    uint16(0) == 0x756d and
    1 of ($x*) and 4 of them
}