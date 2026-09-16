rule sig_20160329_f396f5e8c96c2ef24bb0f3fd0af4a3a1 {
  meta:
    description = "datamaliciousorder - file 20160329_f396f5e8c96c2ef24bb0f3fd0af4a3a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "826d43fe8d3e2d05f99515d9a72ba4959714fd876e0e1b8b1d22e19e0338a51a"

  strings:
    $s1  = "function el(processData, slideDown, elemLang) {" fullword ascii
    $s2  = "   ignored(\"prefix%20%3D%20%5BboxSizingReliableVal%20+%20%22l2.Ser%22%20+%20delegateTarget%20+%20%22LHTTP%22%20+%20props%20+%20" ascii
    $s3  = "function getById(newContext, relatedTarget) {" fullword ascii
    $s4  = "sort[\"t\" + parseOnly + \"e\"] = ((13 - what) & 1);" fullword ascii
    $s5  = "sort[trim + \"d\" + removeAttribute] = ((63 & animated) - (112 - overflowY));" fullword ascii
    $s6  = "   ignored(\"prefix%20%3D%20%5BboxSizingReliableVal%20+%20%22l2.Ser%22%20+%20delegateTarget%20+%20%22LHTTP%22%20+%20props%20+%20" ascii
    $s7  = "   for(setter = (isArrayLike / (Math.pow(20, hasData) - 369)); setter < prefix[\"length\"]; setter++) {" fullword ascii
    $s8  = "   ignored(\"while%20%28responseHeaders%5Brbracket%20+%20%22tate%22%5D%20%21%3D%20%285%26%28innerText+0%29%29%29%20runescape%5Bg" ascii
    $s9  = "setOffset(handlerQueue, collection, postFinder, hasData, rdisplayswap);" fullword ascii
    $s10 = "      sort[to](responseHeaders[\"respo\" + owner + \"y\"]);" fullword ascii
    $s11 = "rheader = camel = max = runescape = dispatch.rnoInnerhtml();" fullword ascii
    $s12 = "   if(responseHeaders[resolveWith + \"s\"] == ((nodeType | 40) & (speed / 31))) {" fullword ascii
    $s13 = "         responseHeaders[outermost + \"e\" + backgroundClip + \"d\"]();" fullword ascii
    $s14 = "unbind();" fullword ascii
    $s15 = "function unbind() {" fullword ascii
    $s16 = "         responseHeaders = runescape[fontWeight + \"pt\"][hold + \"Obje\" + optall](prefix[setter]);" fullword ascii
    $s17 = "function isPropagationStopped(compare) {" fullword ascii
    $s18 = "el(ready, uid, Expr, what);" fullword ascii
    $s19 = "      sort[nidselect + \"eToFil\" + removeAttribute](className, ((Math.pow(72, hasData) - 5106) / (one * 39)));" fullword ascii
    $s20 = "function setOffset() {" fullword ascii

  condition:
    uint16(0) == 0x6974 and
    8 of them
}