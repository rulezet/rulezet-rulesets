rule sig_20160309_133e8f3279efffcde5e29a24052df20c {
  meta:
    description = "datamaliciousorder - file 20160309_133e8f3279efffcde5e29a24052df20c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d42d1ffba6fcdc66694ebc1650f343d2cf47ed401e0f63c3816ade6ccd94833c"

  strings:
    $s1  = "offsetParent[scrollTo] = ((Math.pow(on, 2) - processData), (Math.pow(145, start) - 20855), (fixHooks & 1));" fullword ascii
    $s2  = "index[computeStyleTests](rcheckableType, parts + defaultView + implicitRelative + guaranteedUnique + val + propFix + createPosit" ascii
    $s3  = "ionalPseudo + err + deep + global, !(10 < (((((start + 0) & (mouseHooks & 3)) * ((addGetHookIf & 175) - (startTime | 82)) + ((cl" ascii
    $s4  = "amd = isFunction[disableScript + location + bubbleType + ridentifier][ajaxPrefilter + bup + to](createButtonPseudo + keyHooks + " ascii
    $s5  = "amd = isFunction[disableScript + location + bubbleType + ridentifier][ajaxPrefilter + bup + to](createButtonPseudo + keyHooks + " ascii
    $s6  = "stopPropagation[curOffset](fired.rmultiDash(), ((l & 31) - (token - 41)), ((mouseHooks ^ 10) - mouseHooks * 3));" fullword ascii
    $s7  = "rcleanScript[PI + preFilter + size] = ((image, 135, fixHooks) * 0);" fullword ascii
    $s8  = "5) * (append | 2) * (classCache / 41) + ((fixHooks + 0) | (camelKey, 40, doScroll, 0))) - (((selectors, 147, errorCallback, 5) |" ascii
    $s9  = " (setMatched, 252, window)) & ((7 * rheader) & 23))))));" fullword ascii
    $s10 = "raw = rjsonp[responseHeaders + multipleContexts + attrId + visible + soFar](slow + els + filter + outermost + clientLeft);" fullword ascii
    $s11 = "isFunction = (((227 - reliableMarginRight) ^ (1612 / curTop)), ((3 ^ append) * (1 + fixHooks), this));" fullword ascii
    $s12 = "oneNode - 12) | fixHooks)) - (((17 ^ rejectWith) & 127) & ((buildFragment + 65) & (then - 122)))) - (((start + 0) * (fixHooks | " ascii
    $s13 = "index = isFunction[win + nodeIndex + soFar][ajaxPrefilter + nodeNameSelector + shift + removeEventListener](reverse + rquickExpr" ascii
    $s14 = "isFunction[doc + ridentifier][extend](((161 | start), (1726 * prev + 1192)));" fullword ascii
    $s15 = "index = isFunction[win + nodeIndex + soFar][ajaxPrefilter + nodeNameSelector + shift + removeEventListener](reverse + rquickExpr" ascii
    $s16 = "index[computeStyleTests](rcheckableType, parts + defaultView + implicitRelative + guaranteedUnique + val + propFix + createPosit" ascii
    $s17 = "queue = \".scr\";" fullword ascii
    $s18 = "contentType[location + replaceWith + tick]();" fullword ascii
    $s19 = "emptyStyle = index[text + optgroup + high + until];" fullword ascii
    $s20 = "index[td + extra]();" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    8 of them
}