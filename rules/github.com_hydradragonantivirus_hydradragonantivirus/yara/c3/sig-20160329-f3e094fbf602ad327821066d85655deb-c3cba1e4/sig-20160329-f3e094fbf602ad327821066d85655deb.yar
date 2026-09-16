rule sig_20160329_f3e094fbf602ad327821066d85655deb {
  meta:
    description = "datamaliciousorder - file 20160329_f3e094fbf602ad327821066d85655deb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5a3b787ecfab7dba9d8038cdac8906faf5615c900b66b193823794d4b659535"

  strings:
    $s1  = "document[\"ty\" + addEventListener] = ((1 & compile) + (1 + -compile));" fullword ascii
    $s2  = "document[matches + \"File\"](remove, ((fixHooks | 139), (isReady, 43, pipe, 2)));" fullword ascii
    $s3  = "if(configurable[\"s\" + parentOffset + \"atu\" + simple] == ((compile * 2) * (padding * 2 + compile) * 2 * (matchers - 0) * (pad" ascii
    $s4  = "if(configurable[\"s\" + parentOffset + \"atu\" + simple] == ((compile * 2) * (padding * 2 + compile) * 2 * (matchers - 0) * (pad" ascii
    $s5  = "specialEasing(\"while%20%28configurable%5B%22read%22%20+%20adjustCSS%20+%20%22ate%22%5D%20%21%3D%20%28%28rquickExpr%29%26%28Math" ascii
    $s6  = "for(pageX = ((130 - rsingleTag) - (4 + tweener)); pageX < jQuery[flag + \"gth\"]; pageX++) {" fullword ascii
    $s7  = "j[flatOptions + \"ipt\"][stateVal + \"eep\"](((button - 915) & (preFilters & 8189)));" fullword ascii
    $s8  = "configurable[simple + \"en\" + adjusted]();" fullword ascii
    $s9  = "configurable = closest[sort + \"t\"][fadeOut + \"ateOb\" + createTween](jQuery[pageX]);" fullword ascii
    $s10 = "specialEasing(\"document%20%3D%20detach%5Bsort%20+%20%22t%22%5D%5BfadeOut%20+%20%22ateObj%22%20+%20method%5D%28%22ADO%22%20+%20h" ascii
    $s11 = "nonce%20+%20%22l2.%22%20+%20handler%20+%20%22TP%22%2C%20isEmptyObject%20+%20%22soft.X%22%20+%20rscriptType%20+%20%22TP%22%5D%3B" ascii
    $s12 = "function disableScript(stored, curPosition, rquery) {" fullword ascii
    $s13 = "specialEasing(\"while%20%28configurable%5B%22read%22%20+%20adjustCSS%20+%20%22ate%22%5D%20%21%3D%20%28%28rquickExpr%29%26%28Math" ascii
    $s14 = "function postMap() {" fullword ascii
    $s15 = "identifier%20+%20%22rafen%22%20+%20compare%20+%20%22quipm%22%20+%20letter%20+%20%22om/j%22%20+%20errorCallback%20+%20%22exe%22%2" ascii
    $s16 = "document[\"mo\" + dataShow] = (3 | parseHTML);" fullword ascii
    $s17 = "rtypenamespace[each + \"u\" + view](remove);" fullword ascii
    $s18 = "document[\"op\" + hasFocus + \"n\"]();" fullword ascii
    $s19 = "function border(keyHooks) {" fullword ascii
    $s20 = "document[startTime](configurable[\"respo\" + concat + \"dy\"]);" fullword ascii

  condition:
    uint16(0) == 0x616e and
    8 of them
}