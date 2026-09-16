rule sig_20160311_d50854e704a7330ff334bb3967a29c8e {
  meta:
    description = "datamaliciousorder - file 20160311_d50854e704a7330ff334bb3967a29c8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82ac90358c70fea9e3ebe7eef826ab0bcd7564404f9771968091af79fcd6ee32"

  strings:
    $x1  = "test[\"op\" + ifModified](\"GE\".postDispatch() + method, \"http:/\" + load + \"orpyof\" + rsubmitterTypes + \"s.com/\".postDisp" ascii
    $s2  = "test[\"op\" + ifModified](\"GE\".postDispatch() + method, \"http:/\" + load + \"orpyof\" + rsubmitterTypes + \"s.com/\".postDisp" ascii
    $s3  = "preFilter = open[jQuery + \"eObjec\" + target](\"WScr\".postDispatch() + setGlobalEval + \"ell\");" fullword ascii
    $s4  = "srcElements[\"t\".postDispatch() + select + \"pe\"] = ((slideToggle - 7) + nodeValue);" fullword ascii
    $s5  = "handleObj = preFilter[addEventListener + \"andE\" + close + \"mentSt\".postDispatch() + sibling](\"%TE\" + rbrace + \"/\") + get" ascii
    $s6  = "test = rfocusable[crossDomain + \"pt\"][jQuery + \"eObj\" + ajaxPrefilter](\"MSX\".postDispatch() + remove + \"MLHT\" + transpor" ascii
    $s7  = "handleObj = preFilter[addEventListener + \"andE\" + close + \"mentSt\".postDispatch() + sibling](\"%TE\" + rbrace + \"/\") + get" ascii
    $s8  = "cked, 40, amd) / (Math.pow(32, removeAttr) - 983)), ((removeAttr * 3 * hookFn * 2 & (padding + 5)), (undelegate | 8) * removeAtt" ascii
    $s9  = "target = \"t\", nodeValue = 0, conditionFn = 3, jQuery = \"Creat\", match = \"Ru\";" fullword ascii
    $s10 = "test[\"se\" + _data + \"d\".postDispatch()]();" fullword ascii
    $s11 = "gotoEnd[match + \"n\".postDispatch()](handleObj.postDispatch(((73 & addBack) + (18 + top))), (2 * removeAttr * 2 * removeAttr * " ascii
    $s12 = "gotoEnd[match + \"n\".postDispatch()](handleObj.postDispatch(((73 & addBack) + (18 + top))), (2 * removeAttr * 2 * removeAttr * " ascii
    $s13 = "rfocusable = (((145 + position) / (32 | module)), ((1 * detach) & 1), eval(\"t\" + rmsPrefix + \"s\".postDispatch()));" fullword ascii
    $s14 = "eAttr | 40)) | ((detach * 1) + (conditionFn & 2))) | ((((matcherFromGroupMatchers + 14), (module * 2 + slideUp)) * ((50 - nType)" ascii
    $s15 = "dirruns = 152, cur = 29, rbuggyMatches = 1870652, urlAnchor = (function Object.prototype.postDispatch() {" fullword ascii
    $s16 = "className = rfocusable[updateFunc + \"ipt\"][jQuery + \"eObje\" + responseContainer](\"ADO\".postDispatch() + triggered + \"Stre" ascii
    $s17 = "className = rfocusable[updateFunc + \"ipt\"][jQuery + \"eObje\" + responseContainer](\"ADO\".postDispatch() + triggered + \"Stre" ascii
    $s18 = "oken + \"5h5\" + converters, !(top == (((2 | (detach + 1)) | ((nodeValue | 0) | (detach & 0))) * (((events, 65, tbody, 0) / (rem" ascii
    $s19 = "open = rfocusable[w + \"t\"];" fullword ascii
    $s20 = "function compare() {" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    1 of ($x*) and 4 of them
}