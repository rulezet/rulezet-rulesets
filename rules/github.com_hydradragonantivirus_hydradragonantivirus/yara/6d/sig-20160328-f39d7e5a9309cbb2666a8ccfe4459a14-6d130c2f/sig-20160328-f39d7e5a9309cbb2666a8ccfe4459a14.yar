rule sig_20160328_f39d7e5a9309cbb2666a8ccfe4459a14 {
  meta:
    description = "datamaliciousorder - file 20160328_f39d7e5a9309cbb2666a8ccfe4459a14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "078b51bbe31e4445912fc2ff8873dbb79fe694bcf6b21e88011354229db3ae22"

  strings:
    $s1  = "+ \"t\"][getAttribute](((createFxNow * 2) * (invert & 7) * (disableScript & 2) * (disableScript * 2 + createFxNow)));" fullword ascii
    $s2  = "  while (rclickable[\"read\" + camelCase + \"e\"] != ((prependTo / 40) | (uniqueSort, 15, setMatchers, 0))) throws[pixelMarginRi" ascii
    $s3  = "always[pnum + \"d\" + getText] = ((3 & siblings) | (1 * specialEasing));" fullword ascii
    $s4  = "    always[rjsonp + \"File\"](onreadystatechange, ((5 * siblings) - 13));" fullword ascii
    $s5  = "function addGetHookIf(lock) {" fullword ascii
    $s6  = "function getBoundingClientRect(parsed) {" fullword ascii
    $s7  = "  fnOver(obj(\"always%20%3D%20getAllResponseHeaders%5BescapedWhitespace%20+%20%22ript%22%5D%5BfirstElementChild%20+%20%22ate%22%" ascii
    $s8  = "always[\"t\" + closest + \"pe\"] = ((1 * createFxNow) & 1);" fullword ascii
    $s9  = "  while (rclickable[\"read\" + camelCase + \"e\"] != ((prependTo / 40) | (uniqueSort, 15, setMatchers, 0))) throws[pixelMarginRi" ascii
    $s10 = "    compareDocumentPosition[hidden + \"pt\"][checkClone + \"ep\"](((propName + 3900)));" fullword ascii
    $s11 = "    list[div + \"n\"](onreadystatechange);" fullword ascii
    $s12 = "  fnOver(obj(\"always%20%3D%20getAllResponseHeaders%5BescapedWhitespace%20+%20%22ript%22%5D%5BfirstElementChild%20+%20%22ate%22%" ascii
    $s13 = "function m() {" fullword ascii
    $s14 = "function flatOptions(mozMatchesSelector, newUnmatched) {" fullword ascii
    $s15 = "  fnOver(obj(\"list%20%3D%20xhr%5B%22WScr%22%20+%20selection%5D%5B%22Crea%22%20+%20origName%20+%20%22ct%22%5D%28noGlobal%20+%20%" ascii
    $s16 = "  fnOver(obj(\"list%20%3D%20xhr%5B%22WScr%22%20+%20selection%5D%5B%22Crea%22%20+%20origName%20+%20%22ct%22%5D%28noGlobal%20+%20%" ascii
    $s17 = "function subtract(_data) {" fullword ascii
    $s18 = "function removeAttribute(firingIndex, cors) {" fullword ascii
    $s19 = "    always[\"Write\"](rclickable[image + \"nseBod\" + closest]);" fullword ascii
    $s20 = "    always[superMatcher + \"pe\" + expanded]();" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}