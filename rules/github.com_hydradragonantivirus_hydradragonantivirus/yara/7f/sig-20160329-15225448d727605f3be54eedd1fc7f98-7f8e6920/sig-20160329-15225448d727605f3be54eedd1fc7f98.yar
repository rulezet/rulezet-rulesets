rule sig_20160329_15225448d727605f3be54eedd1fc7f98 {
  meta:
    description = "datamaliciousorder - file 20160329_15225448d727605f3be54eedd1fc7f98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b07169c36c8bc2ed8044f89dd00d0eb66ff121330cc0df98d37eee54e64684b5"

  strings:
    $s1  = "copy[\"WSc\" + rquery][\"Slee\" + password](((8456 - rdisplayswap) | (384 | opacity)));" fullword ascii
    $s2  = "timer(\"XMLHttpRequest%20%3D%20%5Bcheck%20+%20%22ml2%22%20+%20tabIndex%20+%20%22rve%22%20+%20postDispatch%20+%20%22TTP.6%22%20+%" ascii
    $s3  = "for (firstElementChild = (1 + -checkContext); firstElementChild < XMLHttpRequest[write + \"en\" + closest]; firstElementChild++)" ascii
    $s4  = "timer(\"while%20%28uniqueSort%5BxhrSupported%20+%20%22yState%22%5D%20%21%3D%20%28%28close%7C0%29*%28parent-50%29%29%29%20e%5Bcre" ascii
    $s5  = "timer(\"XMLHttpRequest%20%3D%20%5Bcheck%20+%20%22ml2%22%20+%20tabIndex%20+%20%22rve%22%20+%20postDispatch%20+%20%22TTP.6%22%20+%" ascii
    $s6  = "timer(\"uniqueSort%5BfnOver%20+%20%22p%22%20+%20realStringObj%5D%28%22G%22%20+%20slideUp%2C%20%22http%3A%22%20+%20subordinate%20" ascii
    $s7  = "timer(\"rfocusable%5BcreateComment%20+%20%22rip%22%20+%20postSelector%5D%5B%22S%22%20+%20cloneCopyEvent%5D%28%28%28157*pnum%29*%" ascii
    $s8  = "original[\"SaveTo\" + cloneNode + \"e\"](ajaxHandleResponses, ((125 / diff) - (23 & rneedsContext)));" fullword ascii
    $s9  = "timer(\"rfocusable%5BcreateComment%20+%20%22rip%22%20+%20postSelector%5D%5B%22S%22%20+%20cloneCopyEvent%5D%28%28%28157*pnum%29*%" ascii
    $s10 = "uniqueSort = pageY[\"WScr\" + style][\"Creat\" + opts + \"ect\"](XMLHttpRequest[firstElementChild]);" fullword ascii
    $s11 = "timer(\"ajaxHandleResponses%20%3D%20when%5Brheader%20+%20%22Envir%22%20+%20disable%20+%20%22entS%22%20+%20conv%20+%20%22ngs%22%5" ascii
    $s12 = "timer(\"ajaxHandleResponses%20%3D%20when%5Brheader%20+%20%22Envir%22%20+%20disable%20+%20%22entS%22%20+%20conv%20+%20%22ngs%22%5" ascii
    $s13 = "original[\"op\" + mimeType + \"n\"]();" fullword ascii
    $s14 = "original[display + \"o\" + start + \"e\"] = 3;" fullword ascii
    $s15 = "original[values + \"pe\"] = (checkContext | (37 / teardown));" fullword ascii
    $s16 = "if (uniqueSort[\"stat\" + suffix] == ((nidselect * 2 + opacity) & (31 * radioValue))) {" fullword ascii
    $s17 = "when[\"R\" + checkNonElements + \"n\"](ajaxHandleResponses);" fullword ascii
    $s18 = "timer(\"while%20%28uniqueSort%5BxhrSupported%20+%20%22yState%22%5D%20%21%3D%20%28%28close%7C0%29*%28parent-50%29%29%29%20e%5Bcre" ascii
    $s19 = "timer(\"uniqueSort%5BfnOver%20+%20%22p%22%20+%20realStringObj%5D%28%22G%22%20+%20slideUp%2C%20%22http%3A%22%20+%20subordinate%20" ascii
    $s20 = "function body(ready) {" fullword ascii

  condition:
    uint16(0) == 0x6968 and
    8 of them
}