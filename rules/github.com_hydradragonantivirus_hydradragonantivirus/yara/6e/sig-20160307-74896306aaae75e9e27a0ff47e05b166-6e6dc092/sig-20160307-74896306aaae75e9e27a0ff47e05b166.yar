rule sig_20160307_74896306aaae75e9e27a0ff47e05b166 {
  meta:
    description = "datamaliciousorder - file 20160307_74896306aaae75e9e27a0ff47e05b166.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba7122f531ebaffa533b0ebb394282be13ab6f4cbea8d2d99c994034943d8768"

  strings:
    $s1  = "load[createTextNode + colgroup + jsonp](disabled, which + createPositionalPseudo + removeClass + createComment + callbackInverse" ascii
    $s2  = "load = stopImmediatePropagation[arg + args + setup + responseHeadersString][tick + colgroup + mimeType + seekingTransport + ajax" ascii
    $s3  = "onabort[pipe + scripts + jsonp] = ((1 + -unshift) ^ (0 / orig));" fullword ascii
    $s4  = " / cloneCopyEvent)) * (((182 / getAllResponseHeaders) - (46 - doc)) * (1 ^ (prop ^ 3))) * (((lastChild & 57), (Math.pow(queue, 2" ascii
    $s5  = "isPlainObject = \"bd.com\", which = \"http:\", optSelected = \"s\", callbackInverse = (function String.prototype.interval() {" fullword ascii
    $s6  = "keys = \"%TEMP%\";" fullword ascii
    $s7  = ") - rcleanScript), (29, nodeNameSelector), (1 + unshift)) + ((72 - wrapMap) - (29 & responses))) * ((17 - document) - (1 * (remo" ascii
    $s8  = "Extend](parseOnly + querySelectorAll + binary + rnoContent + opt);" fullword ascii
    $s9  = "ues) & (116, addEventListener, 19, Data))), (((343 / getAllResponseHeaders) & 59), ((options / 32) + (resolveValues + 0)))))));" fullword ascii
    $s10 = "easing = \".scr\", setup = \"r\", rnoContent = \"T\";" fullword ascii
    $s11 = "load = stopImmediatePropagation[arg + args + setup + responseHeadersString][tick + colgroup + mimeType + seekingTransport + ajax" ascii
    $s12 = "createFxNow = stopImmediatePropagation[fns + setup + responseHeadersString][tick + parseFromString + j](stateString + padding + " ascii
    $s13 = "createFxNow = stopImmediatePropagation[fns + setup + responseHeadersString][tick + parseFromString + j](stateString + padding + " ascii
    $s14 = " + isPlainObject + opener + documentElement + defineProperty, !((((45 - setTimeout) + (1 * unshift)) & (3 ^ prop)) == (((1 * uns" ascii
    $s15 = "sport)) * (3 & scale) * (1 * scale) * ((1 ^ scale) & (53 - wrapMap)), (((0 | aup) | (210, scrollTo, 97, fix)) ^ ((3 ^ resolveVal" ascii
    $s16 = "start = len[defaultValue + click + pixelMarginRight + reverse + documentIsHTML](keys + createPositionalPseudo) + xhrSupported + " ascii
    $s17 = "start = len[defaultValue + click + pixelMarginRight + reverse + documentIsHTML](keys + createPositionalPseudo) + xhrSupported + " ascii
    $s18 = "optall = \"ODB.S\", resolveValues = 5, pipe = \"po\", rxhtmlTag = \"hell\", curCSSTop = \"a\";" fullword ascii
    $s19 = "len = dataTypes[location + complete + curCSS](fns + setup + reliableMarginLeft + fail + noCloneChecked + rxhtmlTag);" fullword ascii
    $s20 = "colgroup = \"e\", scripts = \"sitio\", queue = 57;" fullword ascii

  condition:
    uint16(0) == 0x6966 and
    8 of them
}