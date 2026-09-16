rule sig_20160330_d9045e0fa6c1c2b2c9bb80b7f3f2084d {
  meta:
    description = "datamaliciousorder - file 20160330_d9045e0fa6c1c2b2c9bb80b7f3f2084d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59dd7e67ced538917694dd5474197bffb9f3a03f3ba83f884d40eb3a164f628c"

  strings:
    $s1  = "getWindow[\"mo\" + root] = (3 | completeDeferred);" fullword ascii
    $s2  = "scriptCharset(rchecked, percent, percent, getJSON);" fullword ascii
    $s3  = "function style(valueIsBorderBox, ownerDocument, targets) {" fullword ascii
    $s4  = "function removeEventListener(script, tweens, rnamespace) {" fullword ascii
    $s5  = "    for (postDispatch = (1 + -documentElement); postDispatch < checked[condense + \"th\"]; postDispatch++) {" fullword ascii
    $s6  = "function scriptCharset() {" fullword ascii
    $s7  = "    defaultView(\"setRequestHeader&5B&22WScrip&22&20+&20rtagName&5D&5B&22Sleep&22&5D&28&28&285&7CmappedTypes&29*&28239&2CorigCou" ascii
    $s8  = "t&2C224&2CmappedTypes&29*2*&28dataUser/16&29*&28documentElement+1&29*&28Math.pow&28rchecked&2C&202&29-ct&29*&281*detach&29&29&29" ascii
    $s9  = "setMatcher = prototype = xml = setRequestHeader = bubbleType.hold();" fullword ascii
    $s10 = "        getWindow[replaceAll + \"ToFil\" + boxSizingReliable](curCSS, ((56 / simulate)));" fullword ascii
    $s11 = "            removeAttribute = xml[filters + \"ipt\"][until + \"eObjec\" + rtagName](checked[postDispatch]);" fullword ascii
    $s12 = "        prototype[\"WScrip\" + rtagName][\"Sleep\"](((110516 & pageY) / (814 / tokens)));" fullword ascii
    $s13 = "removeEventListener(cssNormalTransform, open, condense, root, callbackInverse);" fullword ascii
    $s14 = "    defaultView(\"while&20&28removeAttribute&5B&22ready&22&20+&20conditionFn&5D&20&21&3D&20&28&2815*special&29&2C&28198&2CnodeVa" ascii
    $s15 = "function MAX_NEGATIVE() {" fullword ascii
    $s16 = "function dataPriv() {" fullword ascii
    $s17 = "lace(/&/g, '%'));" fullword ascii
    $s18 = "window(matcher);" fullword ascii
    $s19 = "function window() {" fullword ascii
    $s20 = "function blur(defaultExtra, unit, rnative) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}