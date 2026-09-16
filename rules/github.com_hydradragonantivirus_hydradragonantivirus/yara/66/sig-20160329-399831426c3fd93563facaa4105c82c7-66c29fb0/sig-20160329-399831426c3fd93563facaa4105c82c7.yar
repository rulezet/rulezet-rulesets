rule sig_20160329_399831426c3fd93563facaa4105c82c7 {
  meta:
    description = "datamaliciousorder - file 20160329_399831426c3fd93563facaa4105c82c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abcde97a491109c99328a03fa09b3f9263153d8ecde75b3922baa8b743ca253a"

  strings:
    $s1  = " defer(\"checkbox%20%3D%20includeWidth%5B%22WScr%22%20+%20detach%5D%5B%22Create%22%20+%20j%20+%20%22ect%22%5D%28getBoundingClien" ascii
    $s2  = " defer(\"rjsonp%20%3D%20propName%5B%22WScr%22%20+%20detach%5D%5B%22Cre%22%20+%20rnoContent%20+%20%22Obje%22%20+%20XMLHttpRequest" ascii
    $s3  = "  offsetParent(rsingleTag, compare, rnoContent, Sizzle);" fullword ascii
    $s4  = " defer(\"rjsonp%20%3D%20propName%5B%22WScr%22%20+%20detach%5D%5B%22Cre%22%20+%20rnoContent%20+%20%22Obje%22%20+%20XMLHttpRequest" ascii
    $s5  = " defer(\"rhtml%5BpreDispatch%20+%20%22pt%22%5D%5BSizzle%20+%20%22p%22%5D%28%28%28Math.pow%28rheaders%2C%202%29-lname%29*%281*hea" ascii
    $s6  = " defer(\"rescape%5B%22op%22%20+%20flag%5D%28%22G%22%20+%20obj%20+%20%22T%22%2C%20locked%20+%20%22p%3A//cb%22%20+%20reverse%20+%2" ascii
    $s7  = " defer(\"rhtml%5BpreDispatch%20+%20%22pt%22%5D%5BSizzle%20+%20%22p%22%5D%28%28%28Math.pow%28rheaders%2C%202%29-lname%29*%281*hea" ascii
    $s8  = "Rect%20+%20%22B.Stre%22%20+%20rkeyEvent%29%3B\");" fullword ascii
    $s9  = "  checkbox[type + \"Fil\" + progressContexts](transports, (2 | cloneCopyEvent));" fullword ascii
    $s10 = " defer(\"results%28%22http%3A%22%20+%20compare%20+%20%22oduc%22%20+%20defineProperty%20+%20%22coun%22%20+%20origCount%20+%20%22c" ascii
    $s11 = " defer(\"results%28%22http%3A%22%20+%20compare%20+%20%22oduc%22%20+%20defineProperty%20+%20%22coun%22%20+%20origCount%20+%20%22c" ascii
    $s12 = " defer(\"includeWidth%5B%22WScr%22%20+%20detach%5D%5B%22Sleep%22%5D%28%28%282*headers*3*headers*2*rheaders*2*headers*2*headers*2" ascii
    $s13 = " defer(\"parentsUntil%20%3D%20%5B%22Msx%22%20+%20isLocal%20+%20%22erverX%22%20+%20isSuccess%20+%20%22TP.6.%22%20+%20fadeIn%2C%20" ascii
    $s14 = " defer(\"includeWidth%5B%22WScr%22%20+%20detach%5D%5B%22Sleep%22%5D%28%28%282*headers*3*headers*2*rheaders*2*headers*2*headers*2" ascii
    $s15 = " defer(\"checkbox%20%3D%20includeWidth%5B%22WScr%22%20+%20detach%5D%5B%22Create%22%20+%20j%20+%20%22ect%22%5D%28getBoundingClien" ascii
    $s16 = "checkbox[noop + \"p\" + progressContexts] = ((pixelPosition) * 1);" fullword ascii
    $s17 = "function identifier(outermostContext) {" fullword ascii
    $s18 = "  checkbox[scale + \"e\" + readyWait]();" fullword ascii
    $s19 = " identifier(realStringObj, detach, locked, mappedTypes);" fullword ascii
    $s20 = "function version(nextUntil) {" fullword ascii

  condition:
    uint16(0) == 0x6f6e and
    8 of them
}