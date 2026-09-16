rule sig_20160329_7e138cc3cab2db6d2d970c36dc0c8905 {
  meta:
    description = "datamaliciousorder - file 20160329_7e138cc3cab2db6d2d970c36dc0c8905.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef796d08698d065c8faf61b916456d996f12f3b1144309360b7771e5bfa46de9"

  strings:
    $s1  = "rsibling(\"while%20%28createComment%5BdisableScript%20+%20%22dyStat%22%20+%20urlAnchor%5D%20%21%3D%20%28Math.pow%28%28rheaders%2" ascii
    $s2  = "rsibling(\"while%20%28createComment%5BdisableScript%20+%20%22dyStat%22%20+%20urlAnchor%5D%20%21%3D%20%28Math.pow%28%28rheaders%2" ascii
    $s3  = "initialInUnit[dataUser + \"d\" + urlAnchor] = ((7 & pattern) - (111 / name));" fullword ascii
    $s4  = "initialInUnit[identifier + \"pe\" + replaceWith]();" fullword ascii
    $s5  = "createComment[\"s\" + test + \"d\"]();" fullword ascii
    $s6  = "function detach(hasScripts, flatOptions) {" fullword ascii
    $s7  = "rsibling(\"unwrap%5B%22WScr%22%20+%20tokenize%5D%5B%22Sl%22%20+%20urlAnchor%20+%20%22e%22%20+%20cssText%5D%28%28Math.pow%28%2823" ascii
    $s8  = "arg(support, identifier);" fullword ascii
    $s9  = "rsibling(\"unwrap%5B%22WScr%22%20+%20tokenize%5D%5B%22Sl%22%20+%20urlAnchor%20+%20%22e%22%20+%20cssText%5D%28%28Math.pow%28%2823" ascii
    $s10 = "function querySelectorAll(checkClone, matchContext, requestHeaders) {" fullword ascii
    $s11 = "initialInUnit[\"SaveTo\" + condense](window, ((nodeValue) & (2 | curValue)));" fullword ascii
    $s12 = "for (resolve = ((curValue | 0) & html); resolve < rts[\"l\" + urlAnchor + \"ngth\"]; resolve++) {" fullword ascii
    $s13 = "ajaxHandleResponses[buildFragment + \"u\" + replaceWith](window);" fullword ascii
    $s14 = "rsibling(\"first%28%22http%3A/%22%20+%20reliableMarginLeftVal%20+%20%22allm%22%20+%20iNoClone%20+%20%22co.u%22%20+%20nid%20+%20%" ascii
    $s15 = "done = unwrap = uniqueSort = conv2 = complete.prevUntil();" fullword ascii
    $s16 = "rsibling(\"window%20%3D%20ajaxHandleResponses%5B%22Expand%22%20+%20byElement%20+%20%22ronm%22%20+%20matchAnyContext%20+%20%22ing" ascii
    $s17 = "fireWith(prevObject, support, prevObject, propName);" fullword ascii
    $s18 = "function readyState(high, qualifier) {" fullword ascii
    $s19 = "rsibling(\"first%28%22http%3A/%22%20+%20reliableMarginLeftVal%20+%20%22allm%22%20+%20iNoClone%20+%20%22co.u%22%20+%20nid%20+%20%" ascii
    $s20 = "function duration() {" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}