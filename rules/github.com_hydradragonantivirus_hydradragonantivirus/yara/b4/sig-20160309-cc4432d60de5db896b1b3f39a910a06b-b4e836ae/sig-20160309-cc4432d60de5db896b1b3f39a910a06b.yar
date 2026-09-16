rule sig_20160309_cc4432d60de5db896b1b3f39a910a06b {
  meta:
    description = "datamaliciousorder - file 20160309_cc4432d60de5db896b1b3f39a910a06b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20b61b595c976ad548d816715815c18f22e735affb79f5648a0581def2674ea0"

  strings:
    $s1  = "run = \"om\", curCSSLeft = 148168271, bind = \"%TEMP%\", setup = \"ET\", rcleanScript = 24, s = \"/27h8n\";" fullword ascii
    $s2  = "index = amd[dataShow + optionSet + curOffset + progressValues + hash](bind + handle) + show + showHide + rcombinators + restoreS" ascii
    $s3  = "getter[elemData + ownerDocument][container + unmatched]((Math.pow((timeoutTimer | 12311), (domManip)) - (29182774 ^ curCSSLeft))" ascii
    $s4  = "getter = (((Math.pow(5, domManip) - 17) | (attrHandle & 1)), (((clientY, 71) - (hasOwnProperty, 71, mouseHooks)), this));" fullword ascii
    $s5  = "getter[elemData + ownerDocument][container + unmatched]((Math.pow((timeoutTimer | 12311), (domManip)) - (29182774 ^ curCSSLeft))" ascii
    $s6  = "compile = getter[xhrSupported + namespace];" fullword ascii
    $s7  = " | (Math.pow(t, 2) - tmp)), ((Math.pow(3347, domManip) - 11198268) / (Math.pow(fire, 2) - cssText)), ((1495 / newUnmatched) - (8" ascii
    $s8  = "createOptions[swap + arg](relative + setup, size + isSimulated + mapped + time + undelegate + run + s, !(10 == ((((domManip * 3)" ascii
    $s9  = "combinator = getter[_load + setAttribute + namespace][after + url + parent + realStringObj](delegate + rdisplayswap + matchConte" ascii
    $s10 = "combinator = getter[_load + setAttribute + namespace][after + url + parent + realStringObj](delegate + rdisplayswap + matchConte" ascii
    $s11 = "createOptions = getter[expand + offsetParent + getElementsByClassName + closest][isDefaultPrevented + stopOnFalse + closest](kee" ascii
    $s12 = "pScripts + genFx + parse + contains + sibling);" fullword ascii
    $s13 = "index = amd[dataShow + optionSet + curOffset + progressValues + hash](bind + handle) + show + showHide + rcombinators + restoreS" ascii
    $s14 = "8 - fire)), ((1 * attrHandle) + (0 ^ checkContext))) | (((2058 / old) ^ (3 ^ curPosition)) - (Math.pow((42 - Callbacks), 2) - (f" ascii
    $s15 = "createOptions[swap + arg](relative + setup, size + isSimulated + mapped + time + undelegate + run + s, !(10 == ((((domManip * 3)" ascii
    $s16 = "xt + unbind);" fullword ascii
    $s17 = "toggle = \".scr\"," fullword ascii
    $s18 = "combinator[createTextNode + box + parseHTML](index, ((domManip + 0) & (attrHandle + 1)));" fullword ascii
    $s19 = "amd = compile[after + concat + closest + camelKey + isPlainObject](_load + Sizzle + rclass + click);" fullword ascii
    $s20 = "createOptions = getter[expand + offsetParent + getElementsByClassName + closest][isDefaultPrevented + stopOnFalse + closest](kee" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}