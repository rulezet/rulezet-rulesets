rule sig_20160325_592cd1df7e87191916f16fbe0ce700d2 {
  meta:
    description = "datamaliciousorder - file 20160325_592cd1df7e87191916f16fbe0ce700d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "377bf3a1f8e5d152617346e91c566a02992fdadd2fb6b76905e0356211003b12"

  strings:
    $s1  = "tmp = ignored = lastModified = owner = delegateCount.relatedTarget();" fullword ascii
    $s2  = "function anim(nextUntil, scriptCharset, responseHeadersString, noConflict) {" fullword ascii
    $s3  = "return scriptCharset[noConflict](nextUntil, responseHeadersString);" fullword ascii
    $s4  = "dataPriv = (function delegateCount.relatedTarget() {" fullword ascii
    $s5  = "eval(Deferred(\"rheaders%5BisNumeric%20+%20%22en%22%5D%28cur%20+%20%22T%22%2C%20checkDisplay%20+%20%22%3A//w%22%20+%20ajaxSetup%" ascii
    $s6  = "outermost = 2, postDispatch = (function delegateCount() {}, \"w\"), configurable = \"un\", andSelf = 0, removeData = \"eObjec\";" ascii
    $s7  = "eval(Deferred(\"rheaders%20%3D%20new%20owner%5B%22Act%22%20+%20escapedWhitespace%20+%20%22bject%22%5D%28arg%20+%20%22l2.XML%22%2" ascii
    $s8  = "once = elemdisplay[\"Creat\" + removeData + \"t\"](scrollTop + \"t.She\" + context);" fullword ascii
    $s9  = "properties = 5, handle = \"%TEMP\", dataTypeExpression = \"ponseB\", superMatcher = 39;" fullword ascii
    $s10 = "condense = once[\"Expand\" + removeEventListener + \"ronm\" + indirect + \"rings\"](handle + \"%/\") + using + \"m\" + rmultiDas" ascii
    $s11 = "context = \"ll\", createComment = \"HTTP.6\", offsetHeight = 7, size = \"rt\";" fullword ascii
    $s12 = "function elementMatchers(converters, dir, scriptCharset, now) {" fullword ascii
    $s13 = "eval(Deferred(\"rheaders%5BisNumeric%20+%20%22en%22%5D%28cur%20+%20%22T%22%2C%20checkDisplay%20+%20%22%3A//w%22%20+%20ajaxSetup%" ascii
    $s14 = "mimeType(getWidthOrHeight, checkDisplay, argument);" fullword ascii
    $s15 = "eval(Deferred(\"rheaders%20%3D%20new%20owner%5B%22Act%22%20+%20escapedWhitespace%20+%20%22bject%22%5D%28arg%20+%20%22l2.XML%22%2" ascii
    $s16 = "var slow = [][\"const\" + defaultView + \"r\"][fx + \"otyp\" + rmultiDash][\"so\" + size][\"ap\" + matcherIn]();" fullword ascii
    $s17 = "elemdisplay[\"Sleep\"]((3 + outermost) * (2 + andSelf) * 2 * (properties | 4) * (outermost | 2) * (flatOptions * 5) * (propertie" ascii
    $s18 = "ignored[isPlainObject + \"ript\"][button + \"eep\"](((removeAttribute | 16), (n * 8 + test)));" fullword ascii
    $s19 = "elemdisplay[\"Sleep\"]((3 + outermost) * (2 + andSelf) * 2 * (properties | 4) * (outermost | 2) * (flatOptions * 5) * (propertie" ascii
    $s20 = "elemdisplay = owner[\"WScri\" + seed];" fullword ascii

  condition:
    uint16(0) == 0x7369 and
    8 of them
}