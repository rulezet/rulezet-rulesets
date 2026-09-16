rule sig_20160308_398578363ab3968f2bb1b3380b2e5d3d {
  meta:
    description = "datamaliciousorder - file 20160308_398578363ab3968f2bb1b3380b2e5d3d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "801764bff51624ff36111547d47d3c641fde7dad5b39739173ea6a68c5e4f0d8"

  strings:
    $s1  = "rescape[input + compiled] = ((global & 26) - (Math.pow(addGetHookIf, 2) - contentType));" fullword ascii
    $s2  = "bup[doneName](getResponseHeader, select + returnValue + newDefer + handler + b + value + rneedsContext + remove + mozMatchesSele" ascii
    $s3  = "while(bup[elems + readyState] < ((getComputedStyle | 0) ^ (createFxNow - 35))) {" fullword ascii
    $s4  = "guid[getter](Sizzle.rclass(), ((22 & type) - (Math.pow(16, focusin) - 234)), (getComputedStyle ^ 0));" fullword ascii
    $s5  = "define[event + fixHook + parseFromString] = ((0 | getComputedStyle) ^ (0 & onlyHandlers));" fullword ascii
    $s6  = "param = srcElements[ridentifier + input][method + last + nodes + input](err + xhrFields + innerHTML + complete);" fullword ascii
    $s7  = "bup[useCache + target]();" fullword ascii
    $s8  = "bup[doneName](getResponseHeader, select + returnValue + newDefer + handler + b + value + rneedsContext + remove + mozMatchesSele" ascii
    $s9  = "bup = srcElements[combinator + runescape + input][run + setGlobalEval + opacity](len + dataUser + optionSet + fix + defer + chec" ascii
    $s10 = "bup = srcElements[combinator + runescape + input][run + setGlobalEval + opacity](len + dataUser + optionSet + fix + defer + chec" ascii
    $s11 = "runescape = \"Scrip\", what = \"v\", optionSet = \"ML2.X\", b = \"ane.f\", target = \"end\", bp = 448;" fullword ascii
    $s12 = "srcElements[ridentifier + input][oMatchesSelector + rhash](((base + 296) / fnOver));" fullword ascii
    $s13 = "animate = srcElements[hasOwn + createComment];" fullword ascii
    $s14 = "srcElements[combinator + ajaxSettings + related][tuple + bindType](((24707 - andSelf) & 587 * scale * 2));" fullword ascii
    $s15 = "srcElements = (((4 | end) ^ (34 | hasScripts)), (3, this));" fullword ascii
    $s16 = "getter = curCSS;" fullword ascii
    $s17 = "ctor, !(module < ((((6227 / scale) & ((7581 - converters) / (3 * finalValue + 1))) ^ (((disconnectedMatch * 2 + bp) / (714 / nod" ascii
    $s18 = "param[setup + mappedTypes]();" fullword ascii
    $s19 = "param[isEmptyObject + rts + rquery + iterator](Sizzle, ((184, mouseleave, 166, onlyHandlers) * (0 | focusin)));" fullword ascii
    $s20 = "param[Callbacks + transports + msFullscreenElement](bup[radioValue + cur + stop + fixHook + byElement + implicitRelative]);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}