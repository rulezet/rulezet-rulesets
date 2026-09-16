rule sig_20160329_28802e12769a32f428ed0533bffff121 {
  meta:
    description = "datamaliciousorder - file 20160329_28802e12769a32f428ed0533bffff121.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de76a60e5149bf2f15bd754c3f583e89b39c65837ea272c45a3d9b7d5655cff6"

  strings:
    $s1  = "token(\"show%5B%22op%22%20+%20readyState%5D%28%22G%22%20+%20readyList%20+%20%22T%22%2C%20acceptData%20+%20%22/fanco%22%20+%20i%2" ascii
    $s2  = "token(\"source%20%3D%20%5BfadeToggle%20+%20%22l2.Se%22%20+%20pixelMarginRight%20+%20%22LHTTP.%22%20+%20opener%2C%20%22Msx%22%20+" ascii
    $s3  = "for (marginDiv = ((using - 15) + -(hover - 19)); marginDiv < source[\"leng\" + getAttributeNode]; marginDiv++) {" fullword ascii
    $s4  = "attaches[getElementById + \"ipt\"][idx + \"p\"]((Math.pow((location / 43), (preFilter / 26)) - (firing - 16560331)));" fullword ascii
    $s5  = "if (show[parentsUntil + \"us\"] == (Math.pow((44 * ret + 30), (ret | 0)) - (rquickExpr / 22))) {" fullword ascii
    $s6  = "function prepend(relatedTarget, startTime) {" fullword ascii
    $s7  = "token(\"fx%20%3D%20useCache%5B%22WScr%22%20+%20target%5D%5B%22Crea%22%20+%20noCloneChecked%20+%20%22ject%22%5D%28getElementById%" ascii
    $s8  = "token(\"fx%20%3D%20useCache%5B%22WScr%22%20+%20target%5D%5B%22Crea%22%20+%20noCloneChecked%20+%20%22ject%22%5D%28getElementById%" ascii
    $s9  = "show[getById + \"e\" + handle]();" fullword ascii
    $s10 = "offsetParent[clientY + \"d\" + getBoundingClientRect] = (115, clone);" fullword ascii
    $s11 = "getClientRects(option, readyState);" fullword ascii
    $s12 = "token(\"show%5B%22op%22%20+%20readyState%5D%28%22G%22%20+%20readyList%20+%20%22T%22%2C%20acceptData%20+%20%22/fanco%22%20+%20i%2" ascii
    $s13 = "token(\"source%20%3D%20%5BfadeToggle%20+%20%22l2.Se%22%20+%20pixelMarginRight%20+%20%22LHTTP.%22%20+%20opener%2C%20%22Msx%22%20+" ascii
    $s14 = "function getClientRects(originalProperties, special) {" fullword ascii
    $s15 = "fx[\"R\" + fired + \"n\"](constructor);" fullword ascii
    $s16 = "token(\"while%20%28show%5B%22rea%22%20+%20fadeIn%20+%20%22ate%22%5D%20%21%3D%20%28%2853-type%29+%281*ret%29%29%29%20getClass%5Bg" ascii
    $s17 = "token(\"while%20%28show%5B%22rea%22%20+%20fadeIn%20+%20%22ate%22%5D%20%21%3D%20%28%2853-type%29+%281*ret%29%29%29%20getClass%5Bg" ascii
    $s18 = "offsetParent[dataAndEvents + \"File\"](constructor, ((ret)));" fullword ascii
    $s19 = "offsetParent[\"Wri\" + stored](show[\"respo\" + createFxNow + \"ody\"]);" fullword ascii
    $s20 = "dataTypeOrTransport(optionSet, handle, pixelMarginRight, rfocusMorph, preFilter);" fullword ascii

  condition:
    uint16(0) == 0x6976 and
    8 of them
}