rule sig_20160308_a6a42ce73ec5d1d047b26182a0e9767f {
  meta:
    description = "datamaliciousorder - file 20160308_a6a42ce73ec5d1d047b26182a0e9767f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af7a3d4298144311e8d03720808e7c38ab6c15b1133dd0883ac03a8a345c9e05"

  strings:
    $s1  = "after[defaultValue](hasOwn, webkitMatchesSelector + detach + fixInput + transport + target + structure + isHidden, !(parseFromSt" ascii
    $s2  = "whitespace = superMatcher[rmouseEvent + postDispatch + clearTimeout + oMatchesSelector + clientX + t + onerror + temp + charset]" ascii
    $s3  = "superMatcher = isEmptyObject[blur + sourceIndex + createInputPseudo + firingIndex + temp](max + fix + password + checkContext);" fullword ascii
    $s4  = "whitespace = superMatcher[rmouseEvent + postDispatch + clearTimeout + oMatchesSelector + clientX + t + onerror + temp + charset]" ascii
    $s5  = "after[defaultValue](hasOwn, webkitMatchesSelector + detach + fixInput + transport + target + structure + isHidden, !(parseFromSt" ascii
    $s6  = "xml = (((14 ^ hasOwnProperty) ^ (Math.pow(35, msg) - 1162)), (((domManip / 36) / (completed - 53)), this));" fullword ascii
    $s7  = "postDispatch = \"xp\", password = \"t.Shel\", max = \"WSc\", lname = \"s\", tweeners = \"eam\", domManip = 25200;" fullword ascii
    $s8  = "after = xml[defineProperty + temp][andSelf + marginLeft + escaped](postFilter + top + hasFocus + oldCache + check);" fullword ascii
    $s9  = "xml[stateString + elementMatchers + temp][DOMParser + siblings + noBubble](((14 * cors + 10) ^ (inPage & 8188)));" fullword ascii
    $s10 = "var target = \"huis.\"," fullword ascii
    $s11 = "Symbol[disableScript](whitespace.th(), (accepts / 2 * msg * 3 * msg), (0 ^ (accepts ^ 0)));" fullword ascii
    $s12 = ", 2)) - (checkClone - 2))) & (((handlerQueue / 32) & (msg ^ 9)) ^ ((locked - 39) | (finalValue | 5)))) & (((node * 1) & (node & " ascii
    $s13 = "xml[timers + camel + id][tag + string](((162 - exports) | (166 - marginDiv)));" fullword ascii
    $s14 = "ring < ((((Math.pow((30 & detectDuplicates), (11 - marginRight)) - (194, tweener)) - (Math.pow((Math.pow(9, msg) - 67), (disable" ascii
    $s15 = "col = \"ADO\", firingIndex = \"bjec\", next = \"adys\", elementMatchers = \"crip\", pdataCur = \".scr\";" fullword ascii
    $s16 = "temp = \"t\"," fullword ascii
    $s17 = "selected = \"tate\", parseFromString = 10, andSelf = \"C\", postFilter = \"MSXML\";" fullword ascii
    $s18 = "cssText[rmargin + selection + set] = ((1 * node) * (1 * accepts));" fullword ascii
    $s19 = "(elemLang + animation + argument) + iterator + pdataCur;" fullword ascii
    $s20 = "condense[options + rsubmittable + resolve]();" fullword ascii

  condition:
    uint16(0) == 0x2074 and
    8 of them
}