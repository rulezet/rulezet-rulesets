rule sig_20160328_baba5680689e1dfac8bd02b3c27c5d0b {
  meta:
    description = "datamaliciousorder - file 20160328_baba5680689e1dfac8bd02b3c27c5d0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8d5c8005700718402defeaeece2fd85235aa445aa561e10fa1589a09a977b9a"

  strings:
    $x1  = "eval(charCode(\"method%20%3D%20%28%22p%22%29%2C%20rdisplayswap%20%3D%20%28%220%22%29%3Bassert%20%3D%20%28%22LHT%22%29%2C%20facto" ascii
    $s2  = "   while (responseContainer[\"readyS\" + until] != ((Math.pow(3, originalOptions) - 5))) rhtml[\"WScrip\" + attrs][\"Sl\" + val]" ascii
    $s3  = "readyList[\"m\" + after + \"e\"] = ((25, matchers, 91, selected), (Math.pow(122, originalOptions) - 14714), (code / 40), (fast *" ascii
    $s4  = "readyList[\"m\" + after + \"e\"] = ((25, matchers, 91, selected), (Math.pow(122, originalOptions) - 14714), (code / 40), (fast *" ascii
    $s5  = "   while (responseContainer[\"readyS\" + until] != ((Math.pow(3, originalOptions) - 5))) rhtml[\"WScrip\" + attrs][\"Sl\" + val]" ascii
    $s6  = "n(finalDataType, password, getElementsByTagName, delegateType);" fullword ascii
    $s7  = "readyList[attrs + \"yp\" + get] = fast;" fullword ascii
    $s8  = "         responseContainer = view[contents + \"ript\"][password + \"eObje\" + domManip](removeChild[preferredDoc]);" fullword ascii
    $s9  = "rhtml = rattributeQuotes = binary = view = fns.rkeyEvent();" fullword ascii
    $s10 = "      view[\"WSc\" + uniqueSort][\"Sle\" + get + \"p\"]((5000));" fullword ascii
    $s11 = "refElements(rts, specified, createComment, locked, specified);" fullword ascii
    $s12 = "function addEventListener(isArray) {" fullword ascii
    $s13 = "insertBefore(click, rrun, setFilters, now);" fullword ascii
    $s14 = "      addEventListener(_evalUrl, collection, getElementsByTagName, method, isSimulated);" fullword ascii
    $s15 = "compare(uid);" fullword ascii
    $s16 = "function compare(rparentsprev, rtagName, guid) {" fullword ascii
    $s17 = "      firingIndex(password);" fullword ascii
    $s18 = "function charCode(keyHooks) {" fullword ascii
    $s19 = "function soFar() {" fullword ascii
    $s20 = "function refElements(apply, jsonp, htmlPrefilter) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}