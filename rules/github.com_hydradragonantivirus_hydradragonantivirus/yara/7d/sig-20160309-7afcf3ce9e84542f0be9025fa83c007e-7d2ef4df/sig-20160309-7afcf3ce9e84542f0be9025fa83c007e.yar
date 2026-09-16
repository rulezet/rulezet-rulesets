rule sig_20160309_7afcf3ce9e84542f0be9025fa83c007e {
  meta:
    description = "datamaliciousorder - file 20160309_7afcf3ce9e84542f0be9025fa83c007e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b1a89044d60c19628c9f3675d84ebe6e11b7cdc5b9b9191898172e495131bc3"

  strings:
    $s1  = "list[write](toSelector + checkContext, xml + sortDetached + cors + exports + preferredDoc + values + pdataOld + keepData + rchec" ascii
    $s2  = "75)) | (((teardown - 28) & (getter * 2)) | (fontWeight - 4))) * ((((root - 9) & (ready & 31))) / (((createComment - 36) + (gette" ascii
    $s3  = "r & 1)) + ((Math.pow(compiled, 2) - pseudo), (89 + pseudos), 3))) == transports));" fullword ascii
    $s4  = "getStyles = (((14 | finalText) & (2 | constructor)), ((Math.pow((2 + updateFunc), 2) - nextAll * 2 * p), this));" fullword ascii
    $s5  = "Deferred[value + removeChild + preDispatch + bindType](err, (getter ^ (50 - sibling)));" fullword ascii
    $s6  = "list = getStyles[querySelectorAll + border][script + rcssNum + second](actualDisplay + name + version + getElementsByClassName);" ascii
    $s7  = "on + getAll + factory + insertAfter) + originalEvent + fnOver + subordinate + responseText + transport + subordinate + adjusted " ascii
    $s8  = "err = done[hover + stopImmediatePropagation + getWidthOrHeight + response + tag + groups + value](pageX + stopImmediatePropagati" ascii
    $s9  = "kableType + hasOwn + rhtml + subordinate + excess + rreturn + lname + val, !((((19 | clientTop) - (Math.pow(14, returnValue) - 1" ascii
    $s10 = "pixelMarginRight[readyList](err.onload(), ((8 | setup) - 3 * returnValue * 2 * returnValue), ((0 | end) | (0 & end)));" fullword ascii
    $s11 = "err = done[hover + stopImmediatePropagation + getWidthOrHeight + response + tag + groups + value](pageX + stopImmediatePropagati" ascii
    $s12 = "responses[top + hookFn + subordinate] = ((75, expanded, 199, getter));" fullword ascii
    $s13 = "pageX = \"%T\", hasData = \"en\", transports = 4, version = \"2.XML\", promise = \"bject\";" fullword ascii
    $s14 = "boolHook = getStyles[always + initial];" fullword ascii
    $s15 = "Deferred = getStyles[always + initial][Expr + submit + start + matcher + parentNode + pageY + opts](parentOffset + hold + subord" ascii
    $s16 = "done = boolHook[fire + offset + promise](always + cssProps + postFilter);" fullword ascii
    $s17 = "list[write](toSelector + checkContext, xml + sortDetached + cors + exports + preferredDoc + values + pdataOld + keepData + rchec" ascii
    $s18 = "readyList = trigger + eq + responseText;" fullword ascii
    $s19 = "script = \"Cr\";" fullword ascii
    $s20 = "write = \"open\", pseudo = 21962, setup = 16, border = \"t\", getter = 1, eq = \"u\";" fullword ascii

  condition:
    uint16(0) == 0x7573 and
    8 of them
}