rule sig_20160329_1aa93fd0524580aea5c87b2dc2da666e {
  meta:
    description = "datamaliciousorder - file 20160329_1aa93fd0524580aea5c87b2dc2da666e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcf57c42b04960724f2dbda39f3c6e7552e4420a7c858fa56b03d8847ca97a97"

  strings:
    $s1  = "tmp(string, e, addHandle, target, rdisplayswap);" fullword ascii
    $s2  = "for (newUnmatched = (0 | getAttributeNode); newUnmatched < initial[wrapAll + \"th\"]; newUnmatched++) {" fullword ascii
    $s3  = "firstChild(\"delay%20%3D%20status%5B%22Expan%22%20+%20soFar%20+%20%22vironm%22%20+%20clearInterval%20+%20%22Stri%22%20+%20relate" ascii
    $s4  = "if (css[\"statu\" + string] == ((ajaxHandleResponses & 137), (dirrunsUnique * 4 + shift), (192 | setMatchers))) {" fullword ascii
    $s5  = "globalEval[\"Sav\" + el + \"Fil\" + beforeunload](delay, ((2 & dirrunsUnique)));" fullword ascii
    $s6  = "firstChild(\"while%20%28css%5B%22readyS%22%20+%20structure%20+%20%22e%22%5D%20%21%3D%20%28%28444/hasCompare%29-%282*resolve*2%29" ascii
    $s7  = "firstChild(\"while%20%28css%5B%22readyS%22%20+%20structure%20+%20%22e%22%5D%20%21%3D%20%28%28444/hasCompare%29-%282*resolve*2%29" ascii
    $s8  = "firstChild(\"status%20%3D%20isFunction%5B%22WScr%22%20+%20rnoInnerhtml%5D%5B%22Creat%22%20+%20unique%20+%20%22ct%22%5D%28getWidt" ascii
    $s9  = "firstChild(\"status%20%3D%20isFunction%5B%22WScr%22%20+%20rnoInnerhtml%5D%5B%22Creat%22%20+%20unique%20+%20%22ct%22%5D%28getWidt" ascii
    $s10 = "Text%7C4%29*%28postFilter%2C142%2Cresolve%29+%2882%2Cshift%29%29%29%29%3B\");" fullword ascii
    $s11 = "status[offset + \"un\"](delay);" fullword ascii
    $s12 = "css = isFunction[load + \"pt\"][offsetParent + \"teObje\" + id](initial[newUnmatched]);" fullword ascii
    $s13 = "sort(addEventListener, rnoInnerhtml, eased, soFar);" fullword ascii
    $s14 = "firstChild(\"initial%20%3D%20%5B%22Msxml2%22%20+%20col%20+%20%22rXMLHT%22%20+%20eased%20+%20%220%22%2C%20timerId%20+%20%22l2.X%2" ascii
    $s15 = "function dataTypeOrTransport(mouseleave) {" fullword ascii
    $s16 = "function tmp(createPseudo) {" fullword ascii
    $s17 = "function selectors(readyList, hold) {" fullword ascii
    $s18 = "function overflowX() {" fullword ascii
    $s19 = "function firing() {" fullword ascii
    $s20 = "progress();" fullword ascii

  condition:
    uint16(0) == 0x7573 and
    8 of them
}