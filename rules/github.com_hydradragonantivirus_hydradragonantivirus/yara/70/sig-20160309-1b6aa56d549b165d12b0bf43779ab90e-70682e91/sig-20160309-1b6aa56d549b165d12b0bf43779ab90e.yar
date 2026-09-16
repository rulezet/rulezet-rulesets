rule sig_20160309_1b6aa56d549b165d12b0bf43779ab90e {
  meta:
    description = "datamaliciousorder - file 20160309_1b6aa56d549b165d12b0bf43779ab90e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecb3837926eafbff6c78eced1c1a027efe4c4a8c5502b6965cecb00840e0b8c8"

  strings:
    $x1  = "getElementById[err + lang](jsonp, hasContent + offsetHeight + cssProps + statusCode + off + node + tr + xhr + valHooks + udataCu" ascii
    $s2  = "rtrim[etag + matchesSelector][getElementsByName + href]((Math.pow(MAX_NEGATIVE * 379 * memory, (27 - collection)) - (2365440 | r" ascii
    $s3  = "rtrim[etag + matchesSelector][getElementsByName + href]((Math.pow(MAX_NEGATIVE * 379 * memory, (27 - collection)) - (2365440 | r" ascii
    $s4  = "getElementById[err + lang](jsonp, hasContent + offsetHeight + cssProps + statusCode + off + node + tr + xhr + valHooks + udataCu" ascii
    $s5  = "k, 107), (selectors * 21 + memory), (13, dispatch)) - ((6 * memory + 3) & keyCode * 5)) * ((Math.pow((uid * 4), (height ^ 2)) - " ascii
    $s6  = " (((1998 / getResponseHeader) - 13 * memory * 2) + ((uid * 4) - (uid * 0)))) ^ (((resolveContexts * 4 + collection), (73, addBac" ascii
    $s7  = "v, 2) - next))) / ((2 ^ height) * (6 - selectors) * (2 | memory) | ((27 ^ host) - (39 & globalEventContext)))) * ((((31 & resolv" ascii
    $s8  = "needsContext = xhrFields[ap + triggerHandler + curPosition + nodes + index + isEmptyObject + removeChild](username + fire) + get" ascii
    $s9  = "needsContext = xhrFields[ap + triggerHandler + curPosition + nodes + index + isEmptyObject + removeChild](username + fire) + get" ascii
    $s10 = "rtrim = ((Math.pow(8, memory) - 53) * (memory * 5 + uid), ((7, (v & 13)), this));" fullword ascii
    $s11 = "settings = getElementById[disabled + bulk + handle];" fullword ascii
    $s12 = "(selectors * 2 + uid)) + (1 * (winnow - 12))))));" fullword ascii
    $s13 = "sortDetached[tbody](needsContext.rparentsprev(), ((15 - padding) / (43 | dataTypeExpression)), 0);" fullword ascii
    $s14 = "returnValue = \"re\", getText = \"B\", diff = \"ope\", notify = \"Run\";" fullword ascii
    $s15 = "eContexts), (1 * uid)) + -1) | ((uid + 0) * (leadingRelative, 88, memory)))) == ((((83, memory) ^ (2 * memory + (0 | height))) &" ascii
    $s16 = "crossDomain = rtrim[serializeArray + marginDiv + noConflict + options][toggle + insertBefore + class2type](actualDisplay + getTe" ascii
    $s17 = "crossDomain = rtrim[serializeArray + marginDiv + noConflict + options][toggle + insertBefore + class2type](actualDisplay + getTe" ascii
    $s18 = "getElementById = rtrim[serializeArray + rdashAlpha + matchesSelector][type + rmargin + propName + class2type](htmlPrefilter + or" ascii
    $s19 = "host = 61, offsetHeight = \"ttp:/\", err = \"o\";" fullword ascii
    $s20 = "getElementById = rtrim[serializeArray + rdashAlpha + matchesSelector][type + rmargin + propName + class2type](htmlPrefilter + or" ascii

  condition:
    uint16(0) == 0x616d and
    1 of ($x*) and 4 of them
}