rule sig_20160328_27c53534fe3926f8f894308554e1e59b {
  meta:
    description = "datamaliciousorder - file 20160328_27c53534fe3926f8f894308554e1e59b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f707ba9b4b30160f95c532f76e70675056d2848bb29a6bb2a799fd20e1f82f15"

  strings:
    $s1  = "while (valHooks[throws + \"Sta\" + _removeData] != ((79, globalEval), (35 - invert))) callbackName[\"WScri\" + getWidthOrHeight]" ascii
    $s2  = "eep\"](((Math.pow(20, prefilterOrFactory) - 369), (prefilterOrFactory * 7 * easing * 2), (send - 69)));" fullword ascii
    $s3  = "function getResponseHeader(manipulationTarget, cloneCopyEvent) {" fullword ascii
    $s4  = "while (valHooks[throws + \"Sta\" + _removeData] != ((79, globalEval), (35 - invert))) callbackName[\"WScri\" + getWidthOrHeight]" ascii
    $s5  = "matchesSelector[\"t\" + specified + \"e\"] = ((40 - pseudo) | (1 & rsubmittable));" fullword ascii
    $s6  = "if (valHooks[webkitMatchesSelector + \"atus\"] == ((round - 11) + (html + 50))) {" fullword ascii
    $s7  = "raw(send, getWidthOrHeight, th, combinator, optDisabled);" fullword ascii
    $s8  = "outermost(temp, curOffset, scrollLeft);" fullword ascii
    $s9  = "resolveContexts[\"WScr\" + structure][\"Sle\" + capName](((slow / 31) - (optDisabled / 6)));" fullword ascii
    $s10 = "setAttribute[\"Ru\" + th](submit);" fullword ascii
    $s11 = "matchesSelector[interval + \"p\" + filter + \"n\"]();" fullword ascii
    $s12 = "slideToggle(whitespace(\"assert%5B%22WScr%22%20+%20structure%5D%5B%22Sl%22%20+%20filter%20+%20%22e%22%20+%20charCode%5D%28%28Mat" ascii
    $s13 = "for (transport = ((0 / newContext) | 0); transport < xml[rCRLF + \"ength\"]; transport++) {" fullword ascii
    $s14 = "function outermost() {" fullword ascii
    $s15 = "function pointerleave() {" fullword ascii
    $s16 = "function isNumeric() {" fullword ascii
    $s17 = "function origCount() {" fullword ascii
    $s18 = "pushStack(filter, buildParams);" fullword ascii
    $s19 = "slideToggle(whitespace(\"assert%5B%22WScr%22%20+%20structure%5D%5B%22Sl%22%20+%20filter%20+%20%22e%22%20+%20charCode%5D%28%28Mat" ascii
    $s20 = "function raw(rnoInnerhtml) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}