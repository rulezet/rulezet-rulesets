rule sig_20160311_c21e205fbf5fab2310426a7facd96ced {
  meta:
    description = "datamaliciousorder - file 20160311_c21e205fbf5fab2310426a7facd96ced.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "deaa91d69612cd0d86f55f43442d051e47038c201c05e7a79c01afb91fc1a577"

  strings:
    $s1  = "nodeName[getClass + \"e\" + rscriptTypeMasked](\"GE\".showHide() + detach, \"http:/\" + prepend + \"momsta\" + disable + \"087hg" ascii
    $s2  = "filter[args + \"un\"](notify.showHide(((opacity & 123) & (Math.pow(width, 2) - isLocal))), (1 & defineProperty), ((32 * optgroup" ascii
    $s3  = "nodeName[getClass + \"e\" + rscriptTypeMasked](\"GE\".showHide() + detach, \"http:/\" + prepend + \"momsta\" + disable + \"087hg" ascii
    $s4  = ")) & ((2 * optgroup * 2 | defineProperty) * ((22 + lock) - (5 * lock)) + ((2520 / tr) / (Math.pow(19, optgroup) - 333)))) & (Mat" ascii
    $s5  = "refElements[\"ty\" + parentWindow + \"e\".showHide()] = ((Math.pow(round, 2) - qsa), (196 | sortInput), (Math.pow(7, optgroup) -" ascii
    $s6  = "e() + second, !((((Math.pow((Math.pow(9, optgroup) - 69), (defineProperty | 2)) - (rfocusMorph, 131)) * (optgroup & (10 - define" ascii
    $s7  = "refElements[\"ty\" + parentWindow + \"e\".showHide()] = ((Math.pow(round, 2) - qsa), (196 | sortInput), (Math.pow(7, optgroup) -" ascii
    $s8  = "filter[args + \"un\"](notify.showHide(((opacity & 123) & (Math.pow(width, 2) - isLocal))), (1 & defineProperty), ((32 * optgroup" ascii
    $s9  = "opacity = 89, curElem = \"Respon\", src = 66, disable = \"v.com/\";" fullword ascii
    $s10 = " (src, 84)) / (beforeunload * 2) * (parentOffset + 16))) - (((timers | 440) + (pattern + 326)) - (split)))) > 9));" fullword ascii
    $s11 = "structure[\"op\" + compile]();" fullword ascii
    $s12 = "notify = hide[\"Exp\" + unqueued + \"ironm\" + propName + \"ings\".showHide()](accepts + \"MP%/\") + div1 + \"ments\" + ridentif" ascii
    $s13 = "notify = hide[\"Exp\" + unqueued + \"ironm\" + propName + \"ings\".showHide()](accepts + \"MP%/\") + div1 + \"ments\" + ridentif" ascii
    $s14 = "write = which[remaining + \"ipt\"];" fullword ascii
    $s15 = "Na\".showHide() + percent + \".\" + rdisplayswap + \"r\";" fullword ascii
    $s16 = "hide = write[addHandle + \"Object\"](remaining + \"ipt.Sh\".showHide() + rtagName);" fullword ascii
    $s17 = "which = ((2 * pixelMarginRight), ((13 & each) + (0 | beforeunload)), eval(\"t\" + progressContexts + \"s\".showHide()));" fullword ascii
    $s18 = "nodeName = which[remaining + \"ipt\".showHide()][removeProp + \"ate\" + isXML + \"ct\"](flatOptions + \"ML2\".showHide() + rfocu" ascii
    $s19 = "structure = which[aup + \"rip\".showHide() + fixHook][\"Crea\" + extend + \"ct\"](string + \".Stre\".showHide() + register);" fullword ascii
    $s20 = "nodeName = which[remaining + \"ipt\".showHide()][removeProp + \"ate\" + isXML + \"ct\"](flatOptions + \"ML2\".showHide() + rfocu" ascii

  condition:
    uint16(0) == 0x6977 and
    8 of them
}