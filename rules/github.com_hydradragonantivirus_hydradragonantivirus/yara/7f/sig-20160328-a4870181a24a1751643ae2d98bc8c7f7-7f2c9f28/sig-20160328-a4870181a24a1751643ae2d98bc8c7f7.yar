rule sig_20160328_a4870181a24a1751643ae2d98bc8c7f7 {
  meta:
    description = "datamaliciousorder - file 20160328_a4870181a24a1751643ae2d98bc8c7f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8682e09fca72d96f7af7158a772b64dc922fc7355e1eae57d49ea97223cf4432"

  strings:
    $x1  = "eval(mozMatchesSelector(\"contents%20%3D%20%28%22nd%22%29%3B%20prependTo%20%3D%20%280%29%3B%20noConflict%20%3D%20%28%22tru%22%29" ascii
    $s2  = "while (deep[\"read\" + ajaxExtend + \"e\"] != (Math.pow((stopQueue | 3), rfocusMorph) - (6 - bool))) remove[hasClass + \"ript\"]" ascii
    $s3  = "if (deep[\"s\" + prototype + \"at\" + xml] == (Math.pow((event - 186), (rfocusMorph)) - (Math.pow(12621, rfocusMorph) - 15926939" ascii
    $s4  = "if (deep[\"s\" + prototype + \"at\" + xml] == (Math.pow((event - 186), (rfocusMorph)) - (Math.pow(12621, rfocusMorph) - 15926939" ascii
    $s5  = "e](((2628 / match) - (63, onerror, 46)));" fullword ascii
    $s6  = "function success(tuples, delegateTarget) {" fullword ascii
    $s7  = "while (deep[\"read\" + ajaxExtend + \"e\"] != (Math.pow((stopQueue | 3), rfocusMorph) - (6 - bool))) remove[hasClass + \"ript\"]" ascii
    $s8  = "deep[\"se\" + contents]();" fullword ascii
    $s9  = "function outermostContext(root, emptyGet) {" fullword ascii
    $s10 = "safeActiveElement[\"mo\" + after] = ((28 - noCloneChecked) & (3 & stopQueue));" fullword ascii
    $s11 = "deep = filter[dataTypeExpression + \"pt\"][unit + \"ateO\" + idx](t[tokenize]);" fullword ascii
    $s12 = "copyIsArray(mozMatchesSelector(\"deep%5B%22op%22%20+%20rnoContent%20+%20%22n%22%5D%28prefix%20+%20%22T%22%2C%20MAX_NEGATIVE%20+%" ascii
    $s13 = "copyIsArray(mozMatchesSelector(\"deep%5B%22op%22%20+%20rnoContent%20+%20%22n%22%5D%28prefix%20+%20%22T%22%2C%20MAX_NEGATIVE%20+%" ascii
    $s14 = "eval(mozMatchesSelector(\"contents%20%3D%20%28%22nd%22%29%3B%20prependTo%20%3D%20%280%29%3B%20noConflict%20%3D%20%28%22tru%22%29" ascii
    $s15 = "unqueued[hasClass + \"ript\"][_default + \"p\"](((easing + 5255) - (old, 81, checkbox)));" fullword ascii
    $s16 = "matches(old, dirruns, fast, delegate);" fullword ascii
    $s17 = "function dest(fail, attrNames, removeAttr) {" fullword ascii
    $s18 = "function attaches() {" fullword ascii
    $s19 = "function isFunction(cssFn, add, structure) {" fullword ascii
    $s20 = "function eased(createPositionalPseudo) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}