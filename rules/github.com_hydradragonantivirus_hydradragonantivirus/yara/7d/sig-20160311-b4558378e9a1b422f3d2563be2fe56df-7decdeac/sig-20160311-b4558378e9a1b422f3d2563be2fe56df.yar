rule sig_20160311_b4558378e9a1b422f3d2563be2fe56df {
  meta:
    description = "datamaliciousorder - file 20160311_b4558378e9a1b422f3d2563be2fe56df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56043953cb0d421fcaf05ae36623ee9f4c7ae4bf80de3ffc2fc1aaf976bc4500"

  strings:
    $s1  = "cur[closest + \"pe\" + name](\"G\".parse() + opener, \"http:/\" + compare + \"lit-\" + uniqueCache + \"o.il/3\".parse() + toggle" ascii
    $s2  = "src = (((Math.pow(5, push) - 18) & (prepend - 37)), ((animate & 1) | (deepDataAndEvents * 4 + getStyles)), eval(\"th\" + hasCont" ascii
    $s3  = "prevAll = excess[showHide + \"and\" + setTimeout + \"iron\".parse() + progress + \"tSt\" + reliableMarginLeft](\"%TEMP%\" + crea" ascii
    $s4  = "fixHook[timer + \"u\".parse() + name](prevAll.parse((Math.pow((deepDataAndEvents * 24 + push), (2 & push)) - (5378 | propHooks))" ascii
    $s5  = "k\", !((((1 | getStyles) * (1 + animate)) * ((57, getStyles) + (14 - val)) * (28 - isNumeric)) == (((((Math.pow(147, push) - 213" ascii
    $s6  = "src = (((Math.pow(5, push) - 18) & (prepend - 37)), ((animate & 1) | (deepDataAndEvents * 4 + getStyles)), eval(\"th\" + hasCont" ascii
    $s7  = "prevAll = excess[showHide + \"and\" + setTimeout + \"iron\".parse() + progress + \"tSt\" + reliableMarginLeft](\"%TEMP%\" + crea" ascii
    $s8  = "function getScript() {" fullword ascii
    $s9  = "fixHook[timer + \"u\".parse() + name](prevAll.parse((Math.pow((deepDataAndEvents * 24 + push), (2 & push)) - (5378 | propHooks))" ascii
    $s10 = "pushStack[noConflict + \"p\".parse() + j] = ((1 + animate) & (30 - noBubble));" fullword ascii
    $s11 = "le) + (20 | inspect)), ((23 - newContext)))))));" fullword ascii
    $s12 = "6) - push * 2 * match) * (1 * (animate | 2)) + (deepDataAndEvents * 7 * deepDataAndEvents & 47)) / (((hidden + 79) - push * 3), " ascii
    $s13 = "(selectors + 0) * (settings / 46), ((pdataOld & 59) + (sel - 131)), ((isNumeric & 31) + (animate / 3)))) / ((((push) & (3 + anim" ascii
    $s14 = "tweener = src[\"WScrip\".parse() + high][\"Crea\" + slideToggle + \"ject\"](oMatchesSelector + \"B.Str\".parse() + elemData);" fullword ascii
    $s15 = "cument) + \"s\".parse() + fadeOut + \"z\" + j + \".s\" + fail;" fullword ascii
    $s16 = "cur = src[\"WScr\".parse() + pointerenter][\"Crea\" + bindType + \"ct\"](file + \"ML2.X\".parse() + dataShow + \"P\");" fullword ascii
    $s17 = "cur[preMap + \"en\" + binary]();" fullword ascii
    $s18 = "cur[closest + \"pe\" + name](\"G\".parse() + opener, \"http:/\" + compare + \"lit-\" + uniqueCache + \"o.il/3\".parse() + toggle" ascii
    $s19 = "hasContent = (function Object.prototype.parse() {" fullword ascii
    $s20 = "excess = fragment[\"Create\" + traditional + \"ct\"](uniqueID + \"ipt.S\".parse() + firstChild + \"l\");" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}