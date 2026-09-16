rule sig_20160311_e3caf1e3fc170aa2468564dd23e0041a {
  meta:
    description = "datamaliciousorder - file 20160311_e3caf1e3fc170aa2468564dd23e0041a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97474f23e8adc2d098380300022cdf24190e7e21fb2faee092360241ad7c1117"

  strings:
    $s1  = "serializeArray[matchers + \"pe\" + gotoEnd](\"GE\".parseHTML() + j, \"http\" + computed + \"o.gov.\" + getResponseHeader + \"23r" ascii
    $s2  = "sortInput[animate + \"n\"](jsonp.parseHTML(((78 - fadeTo) + (176 - delegateTarget))), (5 - ignored), ((1 / callbackName) + -(0 |" ascii
    $s3  = "sortInput[animate + \"n\"](jsonp.parseHTML(((78 - fadeTo) + (176 - delegateTarget))), (5 - ignored), ((1 / callbackName) + -(0 |" ascii
    $s4  = "rters & 123), method))), ((31 - getPropertyValue) | (0 | step))) - ((2 & (callbackName * 3)) * ((Math.pow((callbackName * 8), (c" ascii
    $s5  = "HTML() + which, !(3 < (Math.pow((((step & 3) & (unit, 65, bind, 2)) | ((clone * 7 * step, 1) * ((fast / 17), (src + 205), (conve" ascii
    $s6  = "values[linear + \"ToFi\" + matcherFromGroupMatchers](jsonp, ((2 & method) & (37 - p)));" fullword ascii
    $s7  = "fragment = ((2 * bool - (29 & boxSizingReliableVal)), (2 + until) * (2 + until) * (2 | step), eval(\"th\" + value + \"s\".parseH" ascii
    $s8  = "fragment = ((2 * bool - (29 & boxSizingReliableVal)), (2 + until) * (2 + until) * (2 | step), eval(\"th\" + value + \"s\".parseH" ascii
    $s9  = "values = fragment[\"WScri\" + err][\"Create\".parseHTML() + readyList + \"t\"](initial + \"B.S\" + arg + \"am\".parseHTML());" fullword ascii
    $s10 = "allbackName + 1)) - (run & 61)) - ((method + 6) & (until, 13))) + (((memory - 50) * (callbackName * 1)) + (callbackName + -1))))" ascii
    $s11 = "values[abort + \"en\"]();" fullword ascii
    $s12 = "serializeArray = fragment[\"WScr\".parseHTML() + overflowY][\"Create\" + attrHandle + \"ct\"](unique + \".XM\".parseHTML() + mat" ascii
    $s13 = "serializeArray = fragment[\"WScr\".parseHTML() + overflowY][\"Create\" + attrHandle + \"ct\"](unique + \".XM\".parseHTML() + mat" ascii
    $s14 = "self[\"c\" + isSimulated + \"se\".parseHTML()]();" fullword ascii
    $s15 = "propFilter = fragment[scrollTo + \"pt\"];" fullword ascii
    $s16 = "once[useCache + \"y\" + diff] = (amd - 23);" fullword ascii
    $s17 = "var bind = 225," fullword ascii
    $s18 = "computed = (function String.prototype.parseHTML() {" fullword ascii
    $s19 = "var proxy = \"%TE\";" fullword ascii
    $s20 = "jsonp = uniqueCache[not + \"dEnvi\" + bup + \"entS\".parseHTML() + pageXOffset + \"s\"](proxy + \"MP%/\") + isTrigger + \"teedUn" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}