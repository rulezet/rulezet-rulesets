rule sig_20160328_96f932905fb3dea63e56de4ec4e0eec1 {
  meta:
    description = "datamaliciousorder - file 20160328_96f932905fb3dea63e56de4ec4e0eec1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "636f4c71c6c32d91d99742fbbc0ff83004de492b55455bc1e39734bdb7514c3a"

  strings:
    $s1  = "active(setOffset(\"resolveValues%20%3D%20%5BifModified%20+%20%222.Se%22%20+%20valueIsBorderBox%20+%20%22LHTT%22%20+%20preFilter%" ascii
    $s2  = "while (rtrim[\"read\" + box + \"e\"] != (Math.pow(3, (msMatchesSelector & 3)) - (msMatchesSelector * 2 + postFinder))) DOMParser" ascii
    $s3  = "while (rtrim[\"read\" + box + \"e\"] != (Math.pow(3, (msMatchesSelector & 3)) - (msMatchesSelector * 2 + postFinder))) DOMParser" ascii
    $s4  = "isNumeric[\"SaveT\" + rcleanScript](combinator, ((68 - removeProp) / (30 - rmouseEvent)));" fullword ascii
    $s5  = "entLeft + \"rip\" + getText][\"S\" + getComputedStyle](((55 + camel) | (9 - options)));" fullword ascii
    $s6  = "simple[clientLeft + \"ript\"][pop](((3401 + compare) - (992 | rnative)));" fullword ascii
    $s7  = "isNumeric[expand + \"p\" + activeElement] = (postFinder | 0);" fullword ascii
    $s8  = "rtrim = simple[\"WScrip\" + getText][\"Creat\" + buildFragment + \"ect\"](resolveValues[rattributeQuotes]);" fullword ascii
    $s9  = "border(pop, compare, hasContent);" fullword ascii
    $s10 = "defineProperty[mimeType + \"u\" + ret](combinator);" fullword ascii
    $s11 = "Element%20%3D%20%28%22e%22%29%2C%20risSimple%20%3D%20%28%22T%22%29%2C%20postFinder%20%3D%20%281%29%2C%20css%20%3D%20%28%22corei%" ascii
    $s12 = "active(setOffset(\"rtrim%5BisDefaultPrevented%20+%20%22e%22%20+%20ret%5D%28%22GE%22%20+%20risSimple%2C%20%22http%3A%22%20+%20fir" ascii
    $s13 = "function getClientRects(originAnchor, progressValues) {" fullword ascii
    $s14 = "if (rtrim[\"s\" + parseOnly + \"us\"] == ((192 | queue) & (254 & p))) {" fullword ascii
    $s15 = "rtrim[\"se\" + sibling]();" fullword ascii
    $s16 = "active(setOffset(\"combinator%20%3D%20defineProperty%5BremoveAttribute%20+%20%22dEnvi%22%20+%20xml%20+%20%22mentS%22%20+%20nodes" ascii
    $s17 = "active(setOffset(\"combinator%20%3D%20defineProperty%5BremoveAttribute%20+%20%22dEnvi%22%20+%20xml%20+%20%22mentS%22%20+%20nodes" ascii
    $s18 = "active(setOffset(\"rtrim%5BisDefaultPrevented%20+%20%22e%22%20+%20ret%5D%28%22GE%22%20+%20risSimple%2C%20%22http%3A%22%20+%20fir" ascii
    $s19 = "function uniqueSort(submit, completed) {" fullword ascii
    $s20 = "active(setOffset(\"version%28%22http%3A%22%20+%20fired%20+%20%22ut.%22%20+%20css%20+%20%22cc.%22%20+%20sortDetached%20+%20%22/NO" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}