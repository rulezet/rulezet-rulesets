rule sig_20160311_f57ab2e28d14cd25f6944ab53ea047bc {
  meta:
    description = "datamaliciousorder - file 20160311_f57ab2e28d14cd25f6944ab53ea047bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7764f43b9f409b2ae81a3c1fd261e6b89f6c521071af6a03d331508e55125b40"

  strings:
    $s1  = "html = handle[eased + \"dEnvir\" + t + \"ent\".webkitMatchesSelector() + getComputedStyle + \"ing\" + matched](\"%TEM\" + pop) +" ascii
    $s2  = "html = handle[eased + \"dEnvir\" + t + \"ent\".webkitMatchesSelector() + getComputedStyle + \"ing\" + matched](\"%TEM\" + pop) +" ascii
    $s3  = "rsingleTag = startTime[newUnmatched + \"ript\".webkitMatchesSelector()][isFunction + \"Obje\" + focusin](\"MSXM\" + postFinder +" ascii
    $s4  = "code[\"R\".webkitMatchesSelector() + td](html.webkitMatchesSelector(((131, cssPrefixes, 9) | (removeData | 80))), ((r20 - 50) - " ascii
    $s5  = "code[\"R\".webkitMatchesSelector() + td](html.webkitMatchesSelector(((131, cssPrefixes, 9) | (removeData | 80))), ((r20 - 50) - " ascii
    $s6  = "rsingleTag[\"op\" + ifModified + \"n\"](curCSS + \"ET\".webkitMatchesSelector(), createTextNode + \"p://ga\" + sort + \"aw.co.\"" ascii
    $s7  = "TT\".webkitMatchesSelector() + disable);" fullword ascii
    $s8  = "rsingleTag[\"se\" + parent + \"d\"]();" fullword ascii
    $s9  = "rsibling[documentIsHTML + \"e\" + parent]();" fullword ascii
    $s10 = "rmouseEvent = startTime[\"WScr\" + simulate];" fullword ascii
    $s11 = "rsingleTag[\"op\" + ifModified + \"n\"](curCSS + \"ET\".webkitMatchesSelector(), createTextNode + \"p://ga\" + sort + \"aw.co.\"" ascii
    $s12 = "handle = rmouseEvent[\"Create\" + leadingRelative](\"WScrip\".webkitMatchesSelector() + fn + \"l\");" fullword ascii
    $s13 = "rations & 7139)) - (stopOnFalse * 2 & returnTrue * 3 * attr))) / (((4 | unwrap) / (9 - outerCache)) * (3 & (cssHooks / 15))))));" ascii
    $s14 = "rsibling = startTime[preFilters + \"ipt\".webkitMatchesSelector()][rootjQuery + \"ateOb\" + calculatePosition](\"ADOD\" + teardo" ascii
    $s15 = "rsibling = startTime[preFilters + \"ipt\".webkitMatchesSelector()][rootjQuery + \"ateOb\" + calculatePosition](\"ADOD\" + teardo" ascii
    $s16 = "return funcName" fullword ascii
    $s17 = "var funcName = this;" fullword ascii
    $s18 = "prefix();" fullword ascii
    $s19 = "function grep() {" fullword ascii
    $s20 = "td = \"un\", unquoted = 12, returnTrue = 3, traditional = 13648, col = \"ynjk\", t = (function Object.prototype.webkitMatchesSel" ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}