rule sig_20160311_4916f41c3187661d521846c617ada598 {
  meta:
    description = "datamaliciousorder - file 20160311_4916f41c3187661d521846c617ada598.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbd5c3b02fde232f44f7983c58e9c8b2905e5d12e881868b8f26a94669fadb48"

  strings:
    $s1  = "w(17, abort) - 259)) | (Math.pow((sortOrder * 29), (responseType - 7)) - (Math.pow(unique, 2) - string))), (2 * (includeWidth) *" ascii
    $s2  = "ebkitMatchesSelector, 2) - first))) / (((Math.pow(3, abort) - 4)) * ((cssNumber / 2) - (nidselect + 2)) * (load - 37) - (Math.po" ascii
    $s3  = "nodeType[\"o\".hasDuplicate() + propFix + \"en\"](until + \"T\", qsaError + \"/50\".hasDuplicate() + beforeunload + \"11.199\" +" ascii
    $s4  = "w(((fixInput, 50) - (rnoInnerhtml * 5 + sortOrder)), (2 & (sortOrder + 2))) - (sortOrder + 1) * (inspect / 27) * (rnoInnerhtml &" ascii
    $s5  = "ng + \"89o8i\" + returnFalse + \"5y4\".hasDuplicate(), !(9 < ((Math.pow((((Math.pow(width, 2) - attrId) * (1 * slideDown) + (Mat" ascii
    $s6  = " (2 + cache) - (7 * abort * 3 | (wait & 62)))) - (((matcherOut * 4 + dir) & (322 * display + 157)) | (Math.pow(slideDown * 7 * w" ascii
    $s7  = "abort = 2, getElementsByName = \"m\";" fullword ascii
    $s8  = "rneedsContext = find[\"WSc\" + wrapInner + \"t\".hasDuplicate()][settings + \"teOb\" + disabled + \"t\"](rheader + \".Strea\".ha" ascii
    $s9  = "rneedsContext = find[\"WSc\" + wrapInner + \"t\".hasDuplicate()][settings + \"teOb\" + disabled + \"t\"](rheader + \".Strea\".ha" ascii
    $s10 = "soFar[\"Ru\".hasDuplicate() + el](_evalUrl.hasDuplicate((78 + includeWidth)), ((1 | sortOrder) + -1), (cache / 29));" fullword ascii
    $s11 = "T\" + write);" fullword ascii
    $s12 = "nodeType[pointerenter + \"en\" + border]();" fullword ascii
    $s13 = "find = ((16 * slideDown + (14 & cssFn)), ((91 * abort + 53), (isArray)), eval(\"th\" + prefix));" fullword ascii
    $s14 = "nodeType[\"o\".hasDuplicate() + propFix + \"en\"](until + \"T\", qsaError + \"/50\".hasDuplicate() + beforeunload + \"11.199\" +" ascii
    $s15 = "concat = 203, rheader = \"ADODB\", first = 2564844017, fixInput = 190, unique = 608, cache = 0;" fullword ascii
    $s16 = "until = \"GE\";" fullword ascii
    $s17 = "param();" fullword ascii
    $s18 = "function param() {" fullword ascii
    $s19 = "wrapInner = \"rip\", rmouseEvent = \"ite\", attrId = 1178, matcherOut = 5467, returned = \"pos\";" fullword ascii
    $s20 = "nodeType = find[noConflict + \"ript\"][mozMatchesSelector + \"eObje\".hasDuplicate() + reliableMarginRight](\"MSXM\" + overflowY" ascii

  condition:
    uint16(0) == 0x6261 and
    8 of them
}