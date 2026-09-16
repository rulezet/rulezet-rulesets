rule sig_20160329_11a551120f67a119a2241d8f8d8ea582 {
  meta:
    description = "datamaliciousorder - file 20160329_11a551120f67a119a2241d8f8d8ea582.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80696b159fd549148e4c94610ff3263f3608012cc26d02b472c85665cd7df1e6"

  strings:
    $s1  = "trim[responses + \"yp\" + addToPrefiltersOrTransports] = ((Math.pow(13, suffix) - 151) - (simple - 7));" fullword ascii
    $s2  = "unshift(\"trim%20%3D%20processData%5Bwrap%20+%20%22pt%22%5D%5BrmouseEvent%20+%20%22eObje%22%20+%20prevAll%5D%28%22ADO%22%20+%20_" ascii
    $s3  = "trim[elemData + \"ToF\" + cssText](msMatchesSelector, ((18 + emptyStyle) / (Math.pow(8, suffix) - 50)));" fullword ascii
    $s4  = "unshift(\"trim%20%3D%20processData%5Bwrap%20+%20%22pt%22%5D%5BrmouseEvent%20+%20%22eObje%22%20+%20prevAll%5D%28%22ADO%22%20+%20_" ascii
    $s5  = "if (className[\"statu\" + contentType] == ((pos * 3 * suffix * 13) - (_data * 2 * pos))) {" fullword ascii
    $s6  = "trim[\"op\" + addToPrefiltersOrTransports + \"n\"]();" fullword ascii
    $s7  = "function script() {" fullword ascii
    $s8  = "script(returnValue, suffix, sort);" fullword ascii
    $s9  = "function clientY(animation, getAttributeNode) {" fullword ascii
    $s10 = "function get(oldfire) {" fullword ascii
    $s11 = "unshift(\"while%20%28className%5B%22ready%22%20+%20%24%20+%20%22e%22%5D%20%21%3D%20%28%28keyHooks*2%29*%28suffix%7C2%29%29%29%20" ascii
    $s12 = "matcher(contentType, cssText, prevAll, sortDetached, optionSet);" fullword ascii
    $s13 = "function backgroundClip(responseHeaders, vendorPropName) {" fullword ascii
    $s14 = "backgroundClip(startLength, rlocalProtocol, hasScripts, fast);" fullword ascii
    $s15 = "unshift(\"trim%5B%22m%22%20+%20rtypenamespace%20+%20%22e%22%5D%20%3D%20%28%281+keyHooks%29+%2842/handlers%29%29%3B\");" fullword ascii
    $s16 = "root(fireGlobals);" fullword ascii
    $s17 = "unshift(\"while%20%28className%5B%22ready%22%20+%20%24%20+%20%22e%22%5D%20%21%3D%20%28%28keyHooks*2%29*%28suffix%7C2%29%29%29%20" ascii
    $s18 = "function div1() {" fullword ascii
    $s19 = "function j() {" fullword ascii
    $s20 = "function unshift(aup) {" fullword ascii

  condition:
    uint16(0) == 0x7472 and
    8 of them
}