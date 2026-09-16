rule sig_20160329_0ce72bd71e394bb8395cb809d7073974 {
  meta:
    description = "datamaliciousorder - file 20160329_0ce72bd71e394bb8395cb809d7073974.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0480471467678c561875d879ecac695e2573eb21867e933aadfbeaefb080dd4"

  strings:
    $s1  = "compiled(\"while%20%28originAnchor%5BscriptCharset%20+%20%22tate%22%5D%20%21%3D%20%28%28tr+18%29/%28originalOptions%265%29%29%29" ascii
    $s2  = "compiled(\"while%20%28originAnchor%5BscriptCharset%20+%20%22tate%22%5D%20%21%3D%20%28%28tr+18%29/%28originalOptions%265%29%29%29" ascii
    $s3  = "disable(restoreScript, getElementsByClassName);" fullword ascii
    $s4  = "originAnchor = attrNames[start + \"t\"][root + \"teObj\" + isTrigger](rparentsprev[parseXML]);" fullword ascii
    $s5  = "setOffset[col + \"e\" + bind]();" fullword ascii
    $s6  = "for (parseXML = ((135 & pageYOffset), (207, source, 0), (computeStyleTests * 0)); parseXML < rparentsprev[marginRight + \"h\"]; " ascii
    $s7  = "for (parseXML = ((135 & pageYOffset), (207, source, 0), (computeStyleTests * 0)); parseXML < rparentsprev[marginRight + \"h\"]; " ascii
    $s8  = "match(rcleanScript, pageYOffset, view);" fullword ascii
    $s9  = "function replaceChild(postSelector) {" fullword ascii
    $s10 = "setPositiveNumber = attrNames = namespace = context = has.getElementById();" fullword ascii
    $s11 = "clearCloneStyle[\"Ru\" + bind](useCache);" fullword ascii
    $s12 = "setOffset[input + \"oFile\"](useCache, (1 + computeStyleTests));" fullword ascii
    $s13 = "function compiled(stateString) {" fullword ascii
    $s14 = "function rbuggyQSA() {" fullword ascii
    $s15 = "function isWindow(resolve, offsetWidth) {" fullword ascii
    $s16 = "isWindow(Sizzle, rnotwhite, start);" fullword ascii
    $s17 = "function groups(prevAll) {" fullword ascii
    $s18 = "function on(map, prototype) {" fullword ascii
    $s19 = "function event(makeArray) {" fullword ascii
    $s20 = "function match(sortDetached) {" fullword ascii

  condition:
    uint16(0) == 0x7261 and
    8 of them
}