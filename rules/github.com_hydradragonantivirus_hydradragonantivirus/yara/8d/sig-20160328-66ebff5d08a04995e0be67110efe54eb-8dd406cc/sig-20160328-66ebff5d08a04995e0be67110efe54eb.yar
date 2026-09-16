rule sig_20160328_66ebff5d08a04995e0be67110efe54eb {
  meta:
    description = "datamaliciousorder - file 20160328_66ebff5d08a04995e0be67110efe54eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dc2a357953cda9c4741329b5e3214453d1ddc5a6749e518c77c0eecfd354bcc"

  strings:
    $s1  = "checkOn(rcleanScript(\"letter%5BpageY%20+%20%22pe%22%20+%20version%5D%28%22GE%22%20+%20key%2C%20%22http%3A/%22%20+%20getBounding" ascii
    $s2  = "checkOn(rcleanScript(\"letter%5BpageY%20+%20%22pe%22%20+%20version%5D%28%22GE%22%20+%20key%2C%20%22http%3A/%22%20+%20getBounding" ascii
    $s3  = "ath.pow(29, radio) - 788)));" fullword ascii
    $s4  = "checkOn(rcleanScript(\"qsa%5B%22WScr%22%20+%20boxSizingReliableVal%5D%5B%22Sle%22%20+%20responseHeadersString%5D%28%28%281*radio" ascii
    $s5  = "checkOn(rcleanScript(\"qsa%5B%22WScr%22%20+%20boxSizingReliableVal%5D%5B%22Sle%22%20+%20responseHeadersString%5D%28%28%281*radio" ascii
    $s6  = "checkOn(rcleanScript(\"selection%20%3D%20inArray%5B%22WScrip%22%20+%20window%5D%5B%22Creat%22%20+%20fnOver%20+%20%22t%22%5D%28co" ascii
    $s7  = "checkOn(rcleanScript(\"selection%20%3D%20inArray%5B%22WScrip%22%20+%20window%5D%5B%22Creat%22%20+%20fnOver%20+%20%22t%22%5D%28co" ascii
    $s8  = "checkOn(rcleanScript(\"letter%20%3D%20errorCallback%5BcompleteDeferred%20+%20%22rip%22%20+%20window%5D%5B%22Cre%22%20+%20backgro" ascii
    $s9  = "checkOn(rcleanScript(\"letter%20%3D%20errorCallback%5BcompleteDeferred%20+%20%22rip%22%20+%20window%5D%5B%22Cre%22%20+%20backgro" ascii
    $s10 = "nativeStatusText[\"SaveT\" + cur + \"le\"](stopQueue, ((119 & step), (169, compile, 180), radio));" fullword ascii
    $s11 = "while (letter[contextBackup + \"ySta\" + callback] != (45, (radio * 2))) inArray[\"WSc\" + eq][\"Sleep\"](((_default * 4 + match" ascii
    $s12 = "cssNumber(which, returned, html, attrNames, rscriptTypeMasked);" fullword ascii
    $s13 = "function rcleanScript(id) {" fullword ascii
    $s14 = "function cssNumber(eventDoc, thead, func) {" fullword ascii
    $s15 = "function scrollTo(postDispatch, currentValue) {" fullword ascii
    $s16 = "nativeStatusText[html + \"p\" + which] = ((1 | returnFalse) * 1);" fullword ascii
    $s17 = "selection[nidselect + \"un\"](stopQueue);" fullword ascii
    $s18 = "letter[\"s\" + setMatchers + \"d\"]();" fullword ascii
    $s19 = "nativeStatusText[\"m\" + rwhitespace + \"e\"] = ((1 | cssNormalTransform) * (12, radio, 246, match));" fullword ascii
    $s20 = "nativeStatusText[\"op\" + which + \"n\"]();" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}