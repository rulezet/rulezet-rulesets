rule sig_20160329_b369392aa3d6d2fb8f4a36af1c7f9d3b {
  meta:
    description = "datamaliciousorder - file 20160329_b369392aa3d6d2fb8f4a36af1c7f9d3b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fade6d9021a5bfaa422857b65b0cce066f37d530d8783d22e7c139f71866b0d"

  strings:
    $s1  = "gotoEnd[scriptCharset + \"p\" + soFar] = ((_default - 41) & (lastModified + 0));" fullword ascii
    $s2  = "when(rcleanScript, clientTop, doAnimation, get);" fullword ascii
    $s3  = "function docElem(relatedTarget) {" fullword ascii
    $s4  = "    for (rscriptTypeMasked = timer; rscriptTypeMasked < init[removeEventListener + \"e\" + rnotwhite + \"h\"]; rscriptTypeMasked" ascii
    $s5  = "    for (rscriptTypeMasked = timer; rscriptTypeMasked < init[removeEventListener + \"e\" + rnotwhite + \"h\"]; rscriptTypeMasked" ascii
    $s6  = "wrapInner = ajaxConvert = types = support = compiled.string();" fullword ascii
    $s7  = "function getAllResponseHeaders() {" fullword ascii
    $s8  = "function when(checkNonElements, getWidthOrHeight, iNoClone) {" fullword ascii
    $s9  = "function access(getWindow, arr) {" fullword ascii
    $s10 = "guaranteedUnique(keyHooks, globalEventContext, callbackContext, empty, addGetHookIf);" fullword ascii
    $s11 = "complete = 713;" fullword ascii
    $s12 = "    prepend(\"while%20%28domManip%5Bsubordinate%20+%20%22dySta%22%20+%20expand%5D%20%21%3D%20%28%28rxhtmlTag%2C144%29/%28keyHook" ascii
    $s13 = "l(clientY, left, unbind, propFilter);" fullword ascii
    $s14 = "function curCSSTop() {" fullword ascii
    $s15 = "function closest() {" fullword ascii
    $s16 = "cond%3B\");" fullword ascii
    $s17 = "function l(selection) {" fullword ascii
    $s18 = "access(webkitMatchesSelector, shift, keepData, subtract, shift);" fullword ascii
    $s19 = "function args(matcherOut, isSimulated) {" fullword ascii
    $s20 = "closest(context, rnotwhite, margin);" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}