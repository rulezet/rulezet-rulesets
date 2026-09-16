rule sig_20160325_72596a076084988d37c8c8b364777014 {
  meta:
    description = "datamaliciousorder - file 20160325_72596a076084988d37c8c8b364777014.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b48ac00936c9898b88c3723123de328ed8a8d222baabcdfdbf05078b537b36cc"

  strings:
    $s1  = "hash = \"R.exe\"," fullword ascii
    $s2  = "var jsonp = [][\"const\" + cssProps + \"or\"][setGlobalEval + \"toty\" + scripts][\"so\" + disabled + \"t\"][minWidth]();" fullword ascii
    $s3  = "related = statusText[\"Cre\" + matcherIn + \"ect\"](transports + \"ript.\" + ready);" fullword ascii
    $s4  = "function rscriptTypeMasked() {" fullword ascii
    $s5  = "eval(jqXHR(\"animate%28%22Respo%22%20+%20abort%20+%20%22y%22%2C%20%28%28Math.pow%28has%2C%202%29-once%29-%284+urlAnchor%29%29%2C" ascii
    $s6  = "function jqXHR(pipe) {" fullword ascii
    $s7  = "tick = related[\"Expand\" + inArray + \"ironme\" + show + \"ings\"](count + \"P%/\") + attrs + \"de\" + valHooks + \"cr\";" fullword ascii
    $s8  = "isArrayLike = new toSelector[subordinate + \"iveX\" + source + \"ect\"](excess + \"DB.\" + resolveValues + \"eam\");" fullword ascii
    $s9  = "function animate(uniqueID, readyState, when, leadingRelative) {" fullword ascii
    $s10 = "activeElement = (function pixelMarginRight.compilerCache() {" fullword ascii
    $s11 = "eval(jqXHR(\"animate%28%22Respo%22%20+%20abort%20+%20%22y%22%2C%20%28%28Math.pow%28has%2C%202%29-once%29-%284+urlAnchor%29%29%2C" ascii
    $s12 = "opener(inArray, rxhtmlTag, isArray, transports, ajaxConvert);" fullword ascii
    $s13 = "return unescape(pipe);" fullword ascii
    $s14 = "timers = \"t\", boxSizingReliableVal = \"n\", runescape = 8, rxhtmlTag = 80946, count = (function pixelMarginRight() {}, \"%TEM" ascii
    $s15 = "function gotoEnd() {" fullword ascii
    $s16 = "function currentValue() {" fullword ascii
    $s17 = "function etag() {" fullword ascii
    $s18 = "function setMatcher() {" fullword ascii
    $s19 = "function opener() {" fullword ascii
    $s20 = "function td() {" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}