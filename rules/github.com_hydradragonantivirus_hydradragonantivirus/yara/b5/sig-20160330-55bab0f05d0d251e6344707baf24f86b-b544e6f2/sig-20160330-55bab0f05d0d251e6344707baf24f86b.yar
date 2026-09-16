rule sig_20160330_55bab0f05d0d251e6344707baf24f86b {
  meta:
    description = "datamaliciousorder - file 20160330_55bab0f05d0d251e6344707baf24f86b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5d5ccb7e4564420daf855099b479875eda17805db3d0e425953b70b441774de"

  strings:
    $s1  = "eval(unescape([\"off&20&3D&20&28&22ect&22&29&2C&20_evalUrl&20&3D&20&28&22MLHTT&22&29&3Bunit&20&3D&20&28&22proto&22&29\", \"&3B&2" ascii
    $s2  = "  timeoutTimer(\"while&20&28active&5Bridentifier&20+&20&22dySta&22&20+&20rscriptTypeMasked&5D&20&21&3D&20&28&2842/version&29*&28" ascii
    $s3  = "function support(currentTarget, context, getElementsByTagName) {" fullword ascii
    $s4  = "  timeoutTimer(\"while&20&28active&5Bridentifier&20+&20&22dySta&22&20+&20rscriptTypeMasked&5D&20&21&3D&20&28&2842/version&29*&28" ascii
    $s5  = "  for (e = ((1 | size) - 1); e < minWidth[compareDocumentPosition + \"e\" + cssFn + \"h\"]; e++) {" fullword ascii
    $s6  = "djustCSS&20&3D&20&28\", \"function&20originalSettings.pseudos&28&29&7Bvar&20getScript&3D&20&5B&5D&5B&22con&22&20+&20urlAnchor&\"" ascii
    $s7  = "solve&20&3D&20&28&22ty&22&29&3B&20password&20&3D&20&28&22ript.&22&29&3B&20removeData&20&3D&2\", \"0&28&22n&22&29&3B&20rxhtmlTag&" ascii
    $s8  = "l[resolve + \"p\" + fnOver] = ((10 | input) / (35 - nextUntil));" fullword ascii
    $s9  = "support(old, html, run);" fullword ascii
    $s10 = "getAttribute(urlAnchor, response);" fullword ascii
    $s11 = "function getAttribute(backgroundClip) {" fullword ascii
    $s12 = "function propFilter(div, overrideMimeType) {" fullword ascii
    $s13 = "  if (active[\"statu\" + styles] == ((2 * err * 2 * sortStable * 5) + (old & 89))) {" fullword ascii
    $s14 = "  timeoutTimer(\"active&5B&22o&22&20+&20nidselect&20+&20&22en&22&5D&28curCSSTop&20+&20&22T&22&2C&20attrNames&20+&20&22/caina&22&" ascii
    $s15 = "function tweens(readyList) {" fullword ascii
    $s16 = "    l[toggleClass](active[\"respo\" + rcleanScript + \"dy\"]);" fullword ascii
    $s17 = "function nodes() {" fullword ascii
    $s18 = "function mappedTypes(clientX, noop, fired) {" fullword ascii
    $s19 = "function undelegate(outermost, pixelMarginRightVal, pattern) {" fullword ascii
    $s20 = "function anim(protocol) {" fullword ascii

  condition:
    uint16(0) == 0x7773 and
    8 of them
}