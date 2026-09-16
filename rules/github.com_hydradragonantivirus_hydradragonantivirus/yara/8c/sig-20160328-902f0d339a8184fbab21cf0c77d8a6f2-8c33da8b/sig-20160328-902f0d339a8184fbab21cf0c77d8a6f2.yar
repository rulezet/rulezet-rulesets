rule sig_20160328_902f0d339a8184fbab21cf0c77d8a6f2 {
  meta:
    description = "datamaliciousorder - file 20160328_902f0d339a8184fbab21cf0c77d8a6f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bc84659e5c59d8b639c41182464dde7af4226d0d2ff80a4b7c197c93db8105a"

  strings:
    $x1  = "eval(clientY(\"timer%20%3D%20%281616%29%3B%20resolveContexts%20%3D%20%28127%29%3B%20fixHooks%20%3D%20%28%22Msx%22%29%3B%20rscrip" ascii
    $s2  = "prefilterOrFactory(clientY(\"parent%5B%22op%22%20+%20map%5D%28%22G%22%20+%20defaultPrevented%20+%20%22T%22%2C%20hasScripts%20+%2" ascii
    $s3  = "while (parent[\"ready\" + documentIsHTML + \"te\"] != ((1 * attrId) + (1 & delegateType))) resolve[duration + \"pt\"][off + \"p" ascii
    $s4  = "if (parent[count] == (Math.pow((180 | hide), (2 + namespace)) - (6465 + returnFalse))) {" fullword ascii
    $s5  = "while (parent[\"ready\" + documentIsHTML + \"te\"] != ((1 * attrId) + (1 & delegateType))) resolve[duration + \"pt\"][off + \"p" ascii
    $s6  = "for (mozMatchesSelector = ((reliableMarginRight + 1) - (rpseudo * 2)); mozMatchesSelector < text[\"length\"]; mozMatchesSelector" ascii
    $s7  = "for (mozMatchesSelector = ((reliableMarginRight + 1) - (rpseudo * 2)); mozMatchesSelector < text[\"length\"]; mozMatchesSelector" ascii
    $s8  = "pattern[\"ty\" + factory + \"e\"] = ((xhrSuccessStatus - 1) * (delegateType & 1));" fullword ascii
    $s9  = "eval(clientY(\"timer%20%3D%20%281616%29%3B%20resolveContexts%20%3D%20%28127%29%3B%20fixHooks%20%3D%20%28%22Msx%22%29%3B%20rscrip" ascii
    $s10 = "prefilterOrFactory(clientY(\"parent%5B%22op%22%20+%20map%5D%28%22G%22%20+%20defaultPrevented%20+%20%22T%22%2C%20hasScripts%20+%2" ascii
    $s11 = "prefilterOrFactory(clientY(\"pattern%5Bajax%20+%20%22t%22%20+%20rscriptTypeMasked%5D%28parent%5B%22res%22%20+%20offsetHeight%20+" ascii
    $s12 = "pattern[className + \"od\" + rscriptTypeMasked] = ((144, htmlPrefilter, 203), (delegateType * 3));" fullword ascii
    $s13 = "prefilterOrFactory(clientY(\"pattern%5Bajax%20+%20%22t%22%20+%20rscriptTypeMasked%5D%28parent%5B%22res%22%20+%20offsetHeight%20+" ascii
    $s14 = "parent = dispatch[orig + \"t\"][select + \"eObje\" + bup](text[mozMatchesSelector]);" fullword ascii
    $s15 = "parent[assert + \"en\" + stopped]();" fullword ascii
    $s16 = "pattern[\"o\" + factory + \"en\"]();" fullword ascii
    $s17 = "function tmp() {" fullword ascii
    $s18 = "animate(compiled, converters, defaultPrefilter, namespace, DOMParser);" fullword ascii
    $s19 = "button();" fullword ascii
    $s20 = "function button() {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}