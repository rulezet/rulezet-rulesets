rule sig_20160325_149796339a9816be158aada63028846d {
  meta:
    description = "datamaliciousorder - file 20160325_149796339a9816be158aada63028846d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62ba32cdcb493fd2a9a887db965cdcc782bd20dae6d6d39a11ed30ef520bfdb9"

  strings:
    $s1  = "getter = isReady[\"Creat\" + augmentWidthOrHeight + \"ect\"](related + \"t.Shel\" + always);" fullword ascii
    $s2  = "isReady[proxy + \"ep\"](((inArray / 2) / (lastChild | 5)));" fullword ascii
    $s3  = "input = getter[\"Expa\" + register + \"ronm\" + srcElements + \"rings\"](original + \"P%/\") + matchedCount + \"cess\" + lname +" ascii
    $s4  = "srcElements = \"entSt\", time = \"le\", tick = \"R\", getText = \"write\", hasCompare = \"ypacie\", parentOffset = \"pe\";" fullword ascii
    $s5  = "function siblingCheck(getComputedStyle) {" fullword ascii
    $s6  = "showHide[progressValues + \"y\" + parentOffset] = ((callbackInverse | 0) * (version - 50));" fullword ascii
    $s7  = "var attrId = [][\"constr\" + tabIndex][\"proto\" + isArrayLike][\"so\" + show][\"a\" + sortStable]();" fullword ascii
    $s8  = "showHide = new computed[copy + \"veXObj\" + reset](\"ADO\" + responseContainer + \"Stream\");" fullword ascii
    $s9  = "show = \"rt\", backgroundClip = \"P.6.\", readyWait = 5341, version = 51, easing = 44;" fullword ascii
    $s10 = "return unescape(getComputedStyle);" fullword ascii
    $s11 = "function addToPrefiltersOrTransports() {" fullword ascii
    $s12 = "addToPrefiltersOrTransports(copy, responseContainer);" fullword ascii
    $s13 = "function completed(check, rtagName, undelegate, pos) {" fullword ascii
    $s14 = "proxy = (function notifyWith() {}, \"Sle\");" fullword ascii
    $s15 = "function removeEventListener(styles, undelegate, newSelector, checkDisplay) {" fullword ascii
    $s16 = "function xhrFields() {" fullword ascii
    $s17 = "function _$() {" fullword ascii
    $s18 = "function fadeIn() {" fullword ascii
    $s19 = "function anim() {" fullword ascii
    $s20 = "function evt() {" fullword ascii

  condition:
    uint16(0) == 0x6163 and
    8 of them
}