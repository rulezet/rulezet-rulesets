rule sig_20160308_4bf76afec5eec3740c232fc416a6ed1f {
  meta:
    description = "datamaliciousorder - file 20160308_4bf76afec5eec3740c232fc416a6ed1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ceae2cc3f95429b376714ead39a52b0c8f03867104a8fa9c82cee3b6425ddb40"

  strings:
    $s1  = "iframe[unbind + condense](copy, random + JSON + mapped + write + rmargin + minWidth + addCombinator + anim, !(triggered < ((((2 " ascii
    $s2  = "pipe[chainable](outermostContext.wrapAll(), ((completed, 135, charset, 0) ^ (rkeyEvent ^ 0)), ((matcherFromTokens & 215), (unque" ascii
    $s3  = " top[crossDomain + func][readyWait + ajaxConvert + animated]((Math.pow(triggered, 2) - parseFromString) * (1 * tfoot) * 5 * (rco" ascii
    $s4  = "27 - fixInput) ^ (1 * rkeyEvent)))) + ((19 ^ option) - (25 + fnOver)) * ((1 & (origCount ^ 0)) ^ (w - 47)))));" fullword ascii
    $s5  = "Count ^ (0 / w))) + (((3 * visible + 1) ^ (readyList ^ 2)), ((Math.pow(col, 2) - runescape) | (199 & getBoundingClientRect)), ((" ascii
    $s6  = "pipe[chainable](outermostContext.wrapAll(), ((completed, 135, charset, 0) ^ (rkeyEvent ^ 0)), ((matcherFromTokens & 215), (unque" ascii
    $s7  = " top[crossDomain + func][readyWait + ajaxConvert + animated]((Math.pow(triggered, 2) - parseFromString) * (1 * tfoot) * 5 * (rco" ascii
    $s8  = "top = (((95, matcherFromTokens, 163, success) ^ (270 - compile)), ((1 & (origCount & 1)), this));" fullword ascii
    $s9  = "getStyles[extra + animated + firstDataType] = ((rnamespace - 42) * (origCount & 1));" fullword ascii
    $s10 = "while (iframe[matchAnyContext + num + append] < ((cssProps & 5) | (rkeyEvent | 0))) {" fullword ascii
    $s11 = "| rkeyEvent) * (1 * visible) * (165, parse), (2 ^ origCount) * 7 * (visible * 3 + tfoot), ((92 & ct) * 2 + (fnOver & 22)), (orig" ascii
    $s12 = "top[originalEvent + visibility][readyWait + isArrayLike]((tfoot * 3 * tfoot * 2 * visible * 113 * visible - (4109 * tfoot + 1190" ascii
    $s13 = "top[originalEvent + visibility][readyWait + isArrayLike]((tfoot * 3 * tfoot * 2 * visible * 113 * visible - (4109 * tfoot + 1190" ascii
    $s14 = "iframe[unbind + condense](copy, random + JSON + mapped + write + rmargin + minWidth + addCombinator + anim, !(triggered < ((((2 " ascii
    $s15 = "_queueHooks = \"WScr\", gotoEnd = \"St\", dirrunsUnique = \"on\", contents = \"eObje\";" fullword ascii
    $s16 = "height[callbackInverse + rbrace + root + textContent](outermostContext, (tfoot + 0));" fullword ascii
    $s17 = "height = top[originalEvent + visibility][setDocument + contents + expand](removeData + dataTypeOrTransport + cache);" fullword ascii
    $s18 = "optDisabled = \"TEMP%\";" fullword ascii
    $s19 = "outermostContext = speeds[simulate + opts + removeProp + valHooks + firstDataType + selector + visibility + gotoEnd + memory](rf" ascii
    $s20 = "ocusable + optDisabled + propName) + start + style + isEmptyObject + root + bp + updateFunc + allTypes;" fullword ascii

  condition:
    uint16(0) == 0x7363 and
    8 of them
}