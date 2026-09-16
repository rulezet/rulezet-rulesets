rule sig_20160329_61d2e79f8d9976944f7e7adec697dce4 {
  meta:
    description = "datamaliciousorder - file 20160329_61d2e79f8d9976944f7e7adec697dce4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56b5ddd7519dce4d561dd1214a141112c7bfb7fdd736abfd0cae8ef82f1d52b9"

  strings:
    $s1  = " clientTop(\"easing%20%3D%20%5B%22Msxml%22%20+%20namespace%20+%20%22erXM%22%20+%20defaultPrevented%20+%20%22TP.6.0%22%2C%20overr" ascii
    $s2  = "  contents[\"SaveT\" + clazz + \"e\"](opt, ((progress | 12) - (removeEventListener, 58, reverse)));" fullword ascii
    $s3  = "contents[fail + \"p\" + origName] = ((29 / removeEventListener) * (24 / tweeners));" fullword ascii
    $s4  = "contents[\"mo\" + elem + \"e\"] = ((51 / tmp) | (1 | register));" fullword ascii
    $s5  = "  contents[\"Write\"](overflowX[crossDomain + \"seB\" + isDefaultPrevented]);" fullword ascii
    $s6  = "  contents[click + \"e\" + expando]();" fullword ascii
    $s7  = " if(overflowX[\"status\"] == ((remove - 94) - (eventHandle + 134))) {" fullword ascii
    $s8  = " clientTop(\"contents%20%3D%20checkbox%5B%22WScri%22%20+%20statusText%5D%5B%22Crea%22%20+%20root%20+%20%22bject%22%5D%28Expr%20+" ascii
    $s9  = " clientTop(\"contents%20%3D%20checkbox%5B%22WScri%22%20+%20statusText%5D%5B%22Crea%22%20+%20root%20+%20%22bject%22%5D%28Expr%20+" ascii
    $s10 = " clientTop(\"while%20%28overflowX%5B%22read%22%20+%20first%5D%20%21%3D%20%286%26%28Math.pow%28amd%2C%202%29-hold%29%29%29%20page" ascii
    $s11 = " clientTop(\"while%20%28overflowX%5B%22read%22%20+%20first%5D%20%21%3D%20%286%26%28Math.pow%28amd%2C%202%29-hold%29%29%29%20page" ascii
    $s12 = "function getWindow(swap, matchers, nid) {" fullword ascii
    $s13 = "function invert(getElementById, rneedsContext) {" fullword ascii
    $s14 = "Offset%5B%22WSc%22%20+%20toggleClass%20+%20%22t%22%5D%5BfireWith%5D%28%28%28159-container%29+%28Math.pow%289%2C%20postDispatch%2" ascii
    $s15 = " for(els = ((25 * amd + 4), (matcher & 215), register); els < easing[\"lengt\" + currentValue]; els++) {" fullword ascii
    $s16 = "   overflowX = checkbox[\"WScrip\" + mozMatchesSelector][\"Creat\" + computeStyleTests + \"ect\"](easing[els]);" fullword ascii
    $s17 = "function curCSS() {" fullword ascii
    $s18 = "function checkClone() {" fullword ascii
    $s19 = "function expanded() {" fullword ascii
    $s20 = "  height(eventHandle, namespace);" fullword ascii

  condition:
    uint16(0) == 0x616c and
    8 of them
}