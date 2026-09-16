rule sig_20160311_2366273b94321e87e5c134725f990437 {
  meta:
    description = "datamaliciousorder - file 20160311_2366273b94321e87e5c134725f990437.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8d390c7df281bb6adbcd813c86c207dd618fb2ee8b2879c0d02705cd248398d"

  strings:
    $s1  = "rcomma = outermost[originalSettings + \"t\"][strAbort + \"Objec\".click() + has](\"MSXM\" + getScript + \"MLHTTP\");" fullword ascii
    $s2  = "rcomma[funescape + \"pe\".click() + elements](\"GE\" + overflowX, \"http:/\" + destElements + \"iho\".click() + apply + \"biz/be" ascii
    $s3  = "runs) + 1))) & ((sibling + 0) * (((sibling + 0) | timers) | ((75 * handle + 24), (exports / 28), (rpseudo / 39))))) == safeActiv" ascii
    $s4  = "Callback + \"ethai\" + dataUser + \"/43t3g\".click() + module, !((((((computeStyleTests / 11) - fontWeight * 3 * handle) + ((4 &" ascii
    $s5  = "resolveValues[\"sav\" + guaranteedUnique + \"ile\".click()](fx, (2 | (sibling + -1)));" fullword ascii
    $s6  = "outermost = (((171, beforeunload, 450) - (buildParams | 208)), ((sibling + 3) + (rneedsContext & 9)), eval(\"th\" + old + \"s\"." ascii
    $s7  = "outermost = (((171, beforeunload, 450) - (buildParams | 208)), ((sibling + 3) + (rneedsContext & 9)), eval(\"th\" + old + \"s\"." ascii
    $s8  = "function rkeyEvent() {" fullword ascii
    $s9  = "setup[\"t\".click() + username + \"p\" + rjsonp] = ((1 * timers) | (1 | sibling));" fullword ascii
    $s10 = "rcomma[funescape + \"pe\".click() + elements](\"GE\" + overflowX, \"http:/\" + destElements + \"iho\".click() + apply + \"biz/be" ascii
    $s11 = "dispatch = stopped[strAbort + \"Objec\" + has](\"WScr\".click() + checkContext + \"ell\");" fullword ascii
    $s12 = "stopped = outermost[returned + \"pt\"];" fullword ascii
    $s13 = "resolveValues = outermost[matcherFromGroupMatchers + \"ript\".click()][mappedTypes + \"eObje\" + end](\"ADO\" + disabled + \"tre" ascii
    $s14 = "fx = dispatch[count + \"andEnv\" + style + \"entS\".click() + position](\"%TEM\" + elemdisplay) + \"conta\" + finish + \".\".cli" ascii
    $s15 = "fx = dispatch[count + \"andEnv\" + style + \"entS\".click() + position](\"%TEM\" + elemdisplay) + \"conta\" + finish + \".\".cli" ascii
    $s16 = "resolveValues = outermost[matcherFromGroupMatchers + \"ript\".click()][mappedTypes + \"eObje\" + end](\"ADO\" + disabled + \"tre" ascii
    $s17 = "style = \"ironm\", rneedsContext = 9, computeStyleTests = 209, originalSettings = \"WScrip\", end = \"ct\", finish = \"ins\";" fullword ascii
    $s18 = "sortDetached = \"Sle\", strAbort = \"Create\", mappedTypes = \"Creat\", exports = 6076, handle = 3;" fullword ascii
    $s19 = "function rreturn() {" fullword ascii
    $s20 = "var count = \"Exp\"," fullword ascii

  condition:
    uint16(0) == 0x7375 and
    8 of them
}