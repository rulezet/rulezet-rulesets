rule sig_20160313_93782207bb36594b0df0fb692733ab22 {
  meta:
    description = "datamaliciousorder - file 20160313_93782207bb36594b0df0fb692733ab22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "409d2a1e09c0cfdf12b9274de494c2ff1cc469c27bb2cb9d68ff396d4fc36568"

  strings:
    $s1  = "attr[\"op\" + scripts + \"n\"](ignored + \"E\" + getText, \"http:/\" + close + \"ellogu\" + strAbort + \"m/70.\" + css, !(6 == (" ascii
    $s2  = "attr[\"op\" + scripts + \"n\"](ignored + \"E\" + getText, \"http:/\" + close + \"ellogu\" + strAbort + \"m/70.\" + css, !(6 == (" ascii
    $s3  = " | 0)) - ((which * 28 + version)))), ((((66 + options), (Math.pow(89, rparentsprev) - 7745), (matchers - 89), (Math.pow(response" ascii
    $s4  = "what[preferredDoc + \"eToFi\" + domManip](propFix, ((Math.pow(prototype, 2) - isHidden) / (Math.pow(12, rparentsprev) - 124)));" fullword ascii
    $s5  = "52, add, 169, send))) - (Math.pow(((Math.pow(49, rparentsprev) - 2313), (MAX_NEGATIVE | 6), (testContext - 1529)), (rparentsprev" ascii
    $s6  = "Container, 2) - rreturn)) - ((38 - onlyHandlers) + (1 + prefix))) + (((162 | adjustCSS), 3 * children * 3) / ((before | 0) | dee" ascii
    $s7  = "propFix = dataTypes[XMLHttpRequest + \"andEn\" + rcssNum + \"nmentS\" + styles](\"%TE\" + tween) + \"defau\" + beforeSend + \"is" ascii
    $s8  = "propFix = dataTypes[XMLHttpRequest + \"andEn\" + rcssNum + \"nmentS\" + styles](\"%TE\" + tween) + \"defau\" + beforeSend + \"is" ascii
    $s9  = "newUnmatched = \"ay\", notifyWith = 118, which = 83942, charCode = 43, close = \"/oh\", getText = \"T\";" fullword ascii
    $s10 = "what[one + \"en\"]();" fullword ascii
    $s11 = "what = this[checkOn + \"ipt\"][focus + \"eObj\" + fix](\"ADOD\" + orig + \"am\");" fullword ascii
    $s12 = "rsibling = this[\"WScrip\" + iNoClone];" fullword ascii
    $s13 = "Unmatched + \".\" + globalEval + \"r\";" fullword ascii
    $s14 = "attr = this[multipleContexts + \"t\"][cleanData + \"ateOb\" + sortOrder](\"MSXM\" + unqueued + \"MLHTT\" + parentsUntil);" fullword ascii
    $s15 = "function ajaxTransport() {" fullword ascii
    $s16 = "var version = 15395," fullword ascii
    $s17 = "holdReady = what;" fullword ascii
    $s18 = "tween = \"MP%/\", add = 106, XMLHttpRequest = \"Exp\", testContext = 3068, isHidden = 1329, adjustCSS = 134;" fullword ascii
    $s19 = "function pageYOffset() {" fullword ascii
    $s20 = "function eventDoc() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}