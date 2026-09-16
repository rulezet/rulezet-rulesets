rule sig_20160328_31ab0e12ce6eb4fd6ef89f543f10d7fe {
  meta:
    description = "datamaliciousorder - file 20160328_31ab0e12ce6eb4fd6ef89f543f10d7fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4132f05d646010ff123c0a42b2489f213358bd7d202f23dbe16f292f534aa7b3"

  strings:
    $s1  = "swap[\"Write\"](ready[firstChild + \"pons\" + getComputedStyle + \"dy\"]);" fullword ascii
    $s2  = "while (ready[\"read\" + firingIndex + \"e\"] != ((getResponseHeader * 1) * (sort * 2))) clearTimeout[invert + \"ipt\"][removeChi" ascii
    $s3  = "while (ready[\"read\" + firingIndex + \"e\"] != ((getResponseHeader * 1) * (sort * 2))) clearTimeout[invert + \"ipt\"][removeChi" ascii
    $s4  = "swap[_ + \"pe\"] = (getResponseHeader);" fullword ascii
    $s5  = "split[\"WScrip\" + createFxNow][\"Sleep\"](((666 * slideToggle + 440) - (cssText - 167)));" fullword ascii
    $s6  = "attrHandle(valueIsBorderBox(\"swap%20%3D%20vendorPropName%5B%22WScrip%22%20+%20createFxNow%5D%5B%22Create%22%20+%20properties%20" ascii
    $s7  = "ready[rsubmitterTypes + \"e\" + second]();" fullword ascii
    $s8  = "ready = clearTimeout[\"WScrip\" + createFxNow][\"Create\" + simulate + \"ect\"](minWidth[qualifier]);" fullword ascii
    $s9  = "attrHandle(valueIsBorderBox(\"ready%5BparseJSON%20+%20%22pe%22%20+%20write%5D%28%22G%22%20+%20inspect%2C%20%22http%3A%22%20+%20p" ascii
    $s10 = "attrHandle(valueIsBorderBox(\"ready%5BparseJSON%20+%20%22pe%22%20+%20write%5D%28%22G%22%20+%20inspect%2C%20%22http%3A%22%20+%20p" ascii
    $s11 = "attrHandle(valueIsBorderBox(\"swap%5Bthen%20+%20%22eToFil%22%20+%20postMap%5D%28makeArray%2C%20%28%281+getResponseHeader%29%7C%2" ascii
    $s12 = "attrHandle(valueIsBorderBox(\"swap%5Bthen%20+%20%22eToFil%22%20+%20postMap%5D%28makeArray%2C%20%28%281+getResponseHeader%29%7C%2" ascii
    $s13 = "adown(rmargin, inspect, postDispatch, simulate);" fullword ascii
    $s14 = "attrHandle(valueIsBorderBox(\"swap%5B%22m%22%20+%20aup%20+%20%22e%22%5D%20%3D%20%28%281*getResponseHeader%29*3%29%3B\"));" fullword ascii
    $s15 = "function div(wrap, head, prop) {" fullword ascii
    $s16 = "bind%20%3D%20%28%22eam%22%29%2C%20toArray%20%3D%20%28%22gs%22%29%2C%20classNames%20%3D%20%283%29%3Bvar%20postMap%20%3D%20%28%22e" ascii
    $s17 = "for (qualifier = ((0 | ajax) | (17, ajax)); qualifier < minWidth[\"lengt\" + scrollTo]; qualifier++) {" fullword ascii
    $s18 = "if (ready[\"status\"] == ((sort * 13 * classNames * 3) & (pseudos + 60))) {" fullword ascii
    $s19 = "attrHandle(valueIsBorderBox(\"input%28styles%20+%20%22%3A//w%22%20+%20completeDeferred%20+%20%22shw.i%22%20+%20removeData%20+%20" ascii
    $s20 = "attrHandle(valueIsBorderBox(\"input%28styles%20+%20%22%3A//w%22%20+%20completeDeferred%20+%20%22shw.i%22%20+%20removeData%20+%20" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}