rule sig_20160308_99bb32d84cc13064071ff93479effd5d {
  meta:
    description = "datamaliciousorder - file 20160308_99bb32d84cc13064071ff93479effd5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "617e5e68b0752054c4a1b0f9ececc61d2e7f83411d29a3878b46141711b1e19c"

  strings:
    $x1  = "startLength = booleans[expand + preventDefault][msg + hasScripts + temp + gotoEnd + preventDefault](ajaxSettings + currentTarget" ascii
    $x2  = "startLength = booleans[expand + preventDefault][msg + hasScripts + temp + gotoEnd + preventDefault](ajaxSettings + currentTarget" ascii
    $s3  = "box = focus[rts + boxSizingReliable + relatedTarget + makeArray + serializeArray + Expr + readyState](setTimeout + sortStable + " ascii
    $s4  = "attrs[pos + s](a, pointerenter + iframe + sel + cssExpand + active + special + getter + rneedsContext, !(defaultPrevented < ((((" ascii
    $s5  = "while (attrs[tweener + obj + XMLHttpRequest] < (Math.pow((0 | removeData), (0 | doAnimation)) - (248, whitespace))) {" fullword ascii
    $s6  = "box = focus[rts + boxSizingReliable + relatedTarget + makeArray + serializeArray + Expr + readyState](setTimeout + sortStable + " ascii
    $s7  = "booleans[nonce + getElementsByClassName + speeds][reject]((Math.pow((18 | reliableMarginRight), 2) - (sortOrder | 1088)));" fullword ascii
    $s8  = "attrs[pos + s](a, pointerenter + iframe + sel + cssExpand + active + special + getter + rneedsContext, !(defaultPrevented < ((((" ascii
    $s9  = "_removeData = \"St\", bool = 21, propFilter = \"deque\", nonce = \"WSc\", relatedTarget = \"viro\";" fullword ascii
    $s10 = "attrs = booleans[nonce + MAX_NEGATIVE][ajaxTransport + fadeTo + height + module](nextAll + responseFields + root + isPlainObject" ascii
    $s11 = "attrs = booleans[nonce + MAX_NEGATIVE][ajaxTransport + fadeTo + height + module](nextAll + responseFields + root + isPlainObject" ascii
    $s12 = "tag = \"eateO\", timer = 12, currentTarget = \".\", second = \"t.Sh\", cssExpand = \"h.\";" fullword ascii
    $s13 = "ready[cssShow + defaultValue] = ((dataTypeOrTransport + 0) | (isFunction, 1));" fullword ascii
    $s14 = "startLength[checkContext + host]();" fullword ascii
    $s15 = "special = \"z/0o\", nextAll = \"MSXM\", dataTypeOrTransport = 1, a = \"GET\", whitespace = 5;" fullword ascii
    $s16 = "startLength[adjusted + rsibling](box, ((0 | doAnimation) & (24 - bool)));" fullword ascii
    $s17 = " ^ (index | 538)) / ((curCSSLeft, 94, toArray) * 2 + (toArray & 9)))) + ((((dataTypeOrTransport ^ 0) * (dataTypeOrTransport & 1)" ascii
    $s18 = "ajaxSettings = \"ADODB\", reject = \"Sleep\", iterator = \"leep\", temp = \"eOb\";" fullword ascii
    $s19 = "structure = \".scr\";" fullword ascii
    $s20 = "startLength[eventHandle](attrs[_$ + originalEvent + el + proxy]);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}