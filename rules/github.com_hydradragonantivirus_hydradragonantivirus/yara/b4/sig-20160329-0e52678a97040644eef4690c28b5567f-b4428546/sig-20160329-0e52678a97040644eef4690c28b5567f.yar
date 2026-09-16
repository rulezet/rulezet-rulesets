rule sig_20160329_0e52678a97040644eef4690c28b5567f {
  meta:
    description = "datamaliciousorder - file 20160329_0e52678a97040644eef4690c28b5567f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3b9b1fbf18fde3f16e1929c03d76d8746094f665b3778fc0e6123d62376a806"

  strings:
    $s1  = "triggered(\"detach%5B%22o%22%20+%20addCombinator%20+%20%22en%22%5D%28flag%20+%20%22T%22%2C%20hasScripts%20+%20%22//fol%22%20+%20" ascii
    $s2  = "triggered(\"detach%5B%22o%22%20+%20addCombinator%20+%20%22en%22%5D%28flag%20+%20%22T%22%2C%20hasScripts%20+%20%22//fol%22%20+%20" ascii
    $s3  = "done[rheader + \"e\" + on]();" fullword ascii
    $s4  = "for(index = ((251, clazz, 251, nextUntil) - (148, optSelected, 11)); index < elementMatcher[tfoot + \"th\"]; index++) {" fullword ascii
    $s5  = "done[\"Save\" + scrollTo + \"ile\"](args, ((7 - preDispatch) & (57 / charCode)));" fullword ascii
    $s6  = "detach[run + \"e\" + rmsPrefix]();" fullword ascii
    $s7  = "done[\"ty\" + addCombinator + \"e\"] = (1 + jsonp);" fullword ascii
    $s8  = "pipe();" fullword ascii
    $s9  = "triggered(\"doScroll%5Bel%20+%20%22rip%22%20+%20focus%5D%5B%22Slee%22%20+%20addCombinator%5D%28%285*%28Math.pow%28copy%2C%202%29" ascii
    $s10 = "triggered(\"doScroll%5Bel%20+%20%22rip%22%20+%20focus%5D%5B%22Slee%22%20+%20addCombinator%5D%28%285*%28Math.pow%28copy%2C%202%29" ascii
    $s11 = "triggered(\"token%28handler%20+%20%22/foll%22%20+%20keyCode%20+%20%22ikes.%22%20+%20nodeValue%20+%20%22/oQeD%22%20+%20duration%2" ascii
    $s12 = "triggered(\"token%28handler%20+%20%22/foll%22%20+%20keyCode%20+%20%22ikes.%22%20+%20nodeValue%20+%20%22/oQeD%22%20+%20duration%2" ascii
    $s13 = "triggered(\"elementMatcher%20%3D%20%5B%22Msx%22%20+%20addHandle%20+%20%22erv%22%20+%20subordinate%20+%20%22TTP%22%20+%20locked%2" ascii
    $s14 = "triggered(\"args%20%3D%20body%5B%22Expand%22%20+%20setMatchers%20+%20%22ronmen%22%20+%20getPropertyValue%20+%20%22ngs%22%5D%28fu" ascii
    $s15 = "triggered(\"args%20%3D%20body%5B%22Expand%22%20+%20setMatchers%20+%20%22ronmen%22%20+%20getPropertyValue%20+%20%22ngs%22%5D%28fu" ascii
    $s16 = "next(flag, hold, rheader);" fullword ascii
    $s17 = "detach = rparentsprev[documentIsHTML + \"t\"][guid + \"teObje\" + origType](elementMatcher[index]);" fullword ascii
    $s18 = "body[nodeType + \"n\"](args);" fullword ascii
    $s19 = "done[\"Writ\" + owner](detach[\"res\" + ajax + \"Body\"]);" fullword ascii
    $s20 = "done[unique + \"od\" + owner] = (2 + (implementation, 188, num));" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    8 of them
}