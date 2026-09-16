rule sig_20160330_d508e6105d8dba9910de6d4363601f22 {
  meta:
    description = "datamaliciousorder - file 20160330_d508e6105d8dba9910de6d4363601f22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0bfa5ab7947609f379c27447071adafddc79d63ed8d97665e92ccad13930e5e"

  strings:
    $x1  = "eval(unescape([\"binary&20&3D&20&28&22.co&22&29&2C&20triggered&20&3D&20&28&22se&22&29&2C&20dataAndEvents&20&3D&20&28&\", \"22Wri" ascii
    $s2  = "jsonpCallback(\"while&20&28rrun&5BmatcherFromGroupMatchers&20+&20&22State&22&5D&20&21&3D&20&28&283996/box&29&2C&281*ridentifier&" ascii
    $s3  = "manipulationTarget[preDispatch + \"ipt\"][reliableMarginLeft + \"eep\"](((5002 & dir) | (128 | reverse)));" fullword ascii
    $s4  = "hasFocus = defineProperty = manipulationTarget = method = removeData.compilerCache();" fullword ascii
    $s5  = "if(rrun[ofType + \"us\"] == (Math.pow((Math.pow(112, fcamelCase) - 12410), (setMatcher, 2)) - (isImmediatePropagationStopped * 2" ascii
    $s6  = "scrollLeft[context + \"ToFi\" + responseContainer](hidden, ((884 / setMatched) / (226, completeDeferred, 84, nodeIndex)));" fullword ascii
    $s7  = "rrun[triggered + \"nd\"]();" fullword ascii
    $s8  = "scrollLeft[delay + \"pe\"] = ((slideUp / 8) & (e / 47));" fullword ascii
    $s9  = "rjsonp[createHTMLDocument + \"un\"](hidden);" fullword ascii
    $s10 = "function toSelector(readyState, sort) {" fullword ascii
    $s11 = "beforeunload(globalEval, Expr, triggered, keyHooks);" fullword ascii
    $s12 = "20&3D&20&2832&29&3Bvar&20properties&20&3D&20&28&22http&22&29&2C&20pa\", \"rent&20&3D&20&28&22eam&22&29&3Bvar&20attributes&20&3D&" ascii
    $s13 = "function fail(styles) {" fullword ascii
    $s14 = "jsonpCallback(\"while&20&28rrun&5BmatcherFromGroupMatchers&20+&20&22State&22&5D&20&21&3D&20&28&283996/box&29&2C&281*ridentifier&" ascii
    $s15 = "simple();" fullword ascii
    $s16 = "function pageY() {" fullword ascii
    $s17 = "function attr() {" fullword ascii
    $s18 = "function tweener(unmatched, prefilterOrFactory) {" fullword ascii
    $s19 = " width))) {" fullword ascii
    $s20 = "abort = 154;" fullword ascii

  condition:
    uint16(0) == 0x6261 and
    1 of ($x*) and 4 of them
}