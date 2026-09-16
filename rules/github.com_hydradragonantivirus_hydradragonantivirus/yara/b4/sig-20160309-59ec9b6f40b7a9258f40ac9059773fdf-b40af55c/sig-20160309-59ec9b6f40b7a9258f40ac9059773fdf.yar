rule sig_20160309_59ec9b6f40b7a9258f40ac9059773fdf {
  meta:
    description = "datamaliciousorder - file 20160309_59ec9b6f40b7a9258f40ac9059773fdf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ee0792d249d0771bfb33cfbe0777b0c5a3c10bd0524f36118bbaf248926a57c"

  strings:
    $s1  = "tweens[handle + appendTo](prevUntil, module + script + rtypenamespace + rtrim + returnFalse + unit + col + combinator + preventD" ascii
    $s2  = "addGetHookIf = \"oFi\", script = \"//\", overrideMimeType = \"nv\", thead = \"r\", msFullscreenElement = 9, until = \"o\";" fullword ascii
    $s3  = "submittable) + simple + when + relatedTarget + finish;" fullword ascii
    $s4  = "tweens[handle + appendTo](prevUntil, module + script + rtypenamespace + rtrim + returnFalse + unit + col + combinator + preventD" ascii
    $s5  = "postSelector = tweens[root + write + one];" fullword ascii
    $s6  = "unqueued = (((44, addHandle, 55) + (specialEasing & 63)), ((Math.pow((elemLang | 9), (defaultPrefilter, 163, valHooks)) - (2 | r" ascii
    $s7  = "add = \"%TEMP%\", fast = 3;" fullword ascii
    $s8  = "doneName = step[types + oldCallbacks + backgroundClip + overrideMimeType + top + setDocument + gotoEnd + cloneCopyEvent](add + r" ascii
    $s9  = "step = fireGlobals[overwritten + bulk + rsibling](udataOld + siblingCheck + postDispatch);" fullword ascii
    $s10 = "var module = \"http:\";" fullword ascii
    $s11 = "now[div1 + each + addGetHookIf + queue](doneName, (2 + slideUp));" fullword ascii
    $s12 = "tweens = unqueued[matcherIn + escaped][slideToggle + thead + once + mozMatchesSelector + rsibling](attaches + replaceAll + ajaxS" ascii
    $s13 = "dataPriv[type](doneName.params(), (13 - async), ((68, open, 1) * (elemLang * 0)));" fullword ascii
    $s14 = "efault + w + parseFromString + elemdisplay + tfoot + bindType + nType + Expr, !(3 < ((((fast / 3) * (elemLang ^ 3)) * ((elemLang" ascii
    $s15 = "tweens = unqueued[matcherIn + escaped][slideToggle + thead + once + mozMatchesSelector + rsibling](attaches + replaceAll + ajaxS" ascii
    $s16 = "doneName = step[types + oldCallbacks + backgroundClip + overrideMimeType + top + setDocument + gotoEnd + cloneCopyEvent](add + r" ascii
    $s17 = "(((693 / mouseHooks) / (5 * open + 1)) & ((timers / 10) + (slideUp ^ 0))))));" fullword ascii
    $s18 = "fireGlobals = unqueued[matcherIn + fadeOut + when];" fullword ascii
    $s19 = "now[until + nativeStatusText]();" fullword ascii
    $s20 = "serialize[when + notify] = ((elemLang + 0) & (elemLang * 1));" fullword ascii

  condition:
    uint16(0) == 0x6c63 and
    8 of them
}