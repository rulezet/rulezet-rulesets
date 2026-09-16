rule sig_20160328_2ecd567f003ec62df52d3127b1de30ad {
  meta:
    description = "datamaliciousorder - file 20160328_2ecd567f003ec62df52d3127b1de30ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d7c1d6b91ef97576d534ce80cabad86f2467c7cb04ef2a7909694d7b47dbe61"

  strings:
    $x1  = "eval(body(\"removeClass%20%3D%20%281728%29%3B%20toggle%20%3D%20%28%22n%22%29%3Breject%20%3D%20%28%22MLH%22%29%2C%20linear%20%3D%" ascii
    $s2  = "ap(body(\"pipe%28script%20+%20%22p%3A/%22%20+%20token%20+%20%22cdzn%22%20+%20props%20+%20%22m/J%22%20+%20cssExpand%20+%20%22.exe" ascii
    $s3  = "ap(body(\"pipe%28script%20+%20%22p%3A/%22%20+%20token%20+%20%22cdzn%22%20+%20props%20+%20%22m/J%22%20+%20cssExpand%20+%20%22.exe" ascii
    $s4  = "while (rheaders[option + \"yStat\" + isArrayLike] != ((Math.pow(14, setAttribute) - 175) - (timers))) offsetWidth[\"WScrip\" + p" ascii
    $s5  = "while (rheaders[option + \"yStat\" + isArrayLike] != ((Math.pow(14, setAttribute) - 175) - (timers))) offsetWidth[\"WScrip\" + p" ascii
    $s6  = "ap(body(\"rheaders%5B%22op%22%20+%20isArrayLike%20+%20%22n%22%5D%28postFinder%20+%20%22T%22%2C%20script%20+%20%22p%3A//sh%22%20+" ascii
    $s7  = "ap(body(\"rheaders%5B%22op%22%20+%20isArrayLike%20+%20%22n%22%5D%28postFinder%20+%20%22T%22%2C%20script%20+%20%22p%3A//sh%22%20+" ascii
    $s8  = "if (rheaders[\"s\" + getAttribute + \"us\"] == ((208, preFilters, 8000) / (step | 40))) {" fullword ascii
    $s9  = "ap(body(\"getPropertyValue%20%3D%20opener%5B%22WSc%22%20+%20pageY%5D%5B%22Creat%22%20+%20hold%20+%20%22ect%22%5D%28capName%20+%2" ascii
    $s10 = "rheaders = offsetWidth[conditionFn + \"ript\"][prop + \"ateO\" + prevAll](emptyGet[rclickable]);" fullword ascii
    $s11 = "getPropertyValue[\"Ru\" + toggle](matched);" fullword ascii
    $s12 = "clone[\"mo\" + cors + \"e\"] = (14 - implementation);" fullword ascii
    $s13 = "ap(body(\"clone%5Bcomplete%20+%20%22rit%22%20+%20isArrayLike%5D%28rheaders%5B%22respo%22%20+%20defaultView%20+%20%22ody%22%5D%29" ascii
    $s14 = "clone[noop + \"pe\"] = ((9 - currentTime) & 1);" fullword ascii
    $s15 = "ap(body(\"clone%5Bcomplete%20+%20%22rit%22%20+%20isArrayLike%5D%28rheaders%5B%22respo%22%20+%20defaultView%20+%20%22ody%22%5D%29" ascii
    $s16 = "TEMP%25%22%29%2C%20noGlobal%20%3D%20%28%22eObjec%22%29%2C%20stopImmediatePropagation%20%3D%20%28function%20tweener%28%29%7B%7D%2" ascii
    $s17 = "offsetWidth[capName + \"t\"][specialEasing](((seed - 3300) - (Math.pow(removeClass, 2) - udataOld)));" fullword ascii
    $s18 = "Selector%20%3D%20%28%22app%22%29%2C%20computeStyleTests%20%3D%20%28%22.XMLHT%22%29%3Bprops%20%3D%20%28%22jh.co%22%29%3B%20token%" ascii
    $s19 = "disconnectedMatch(invert, getAttribute);" fullword ascii
    $s20 = "function content(deepDataAndEvents, extra, deep) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}