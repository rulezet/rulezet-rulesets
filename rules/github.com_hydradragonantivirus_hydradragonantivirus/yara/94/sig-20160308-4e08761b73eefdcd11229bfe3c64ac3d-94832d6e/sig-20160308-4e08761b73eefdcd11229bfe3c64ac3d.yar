rule sig_20160308_4e08761b73eefdcd11229bfe3c64ac3d {
  meta:
    description = "datamaliciousorder - file 20160308_4e08761b73eefdcd11229bfe3c64ac3d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc4a3592a5fddaecaba0111a5650f19a891a5b9bd8af33887558f16b0dcf6ae1"

  strings:
    $s1  = "operator & (186 - args)) - ((5 ^ proxy) + (62 & createTextNode))) ^ ((Math.pow((74, valueIsBorderBox), (2 & proxy)) - (Math.pow(" ascii
    $s2  = "onload[parents + attaches](method + w, offsetParent + cache + childNodes + parts + timers + addHandle + remove + filters, !(((((" ascii
    $s3  = "rsubmittable = groups[charCode + lastChild + rjsonp + head](targets + wrapMap + dataUser + selector);" fullword ascii
    $s4  = "disableScript = \"%TEMP%\";" fullword ascii
    $s5  = "originAnchor = rsubmittable[unique + camelKey + getText + gotoEnd + keepData + inPage + rsingleTag](disableScript + check) + twe" ascii
    $s6  = " / (Math.pow((((Symbol | 186) * (percent + 0)) / (Math.pow(a * 2 * func, (1 ^ proxy)) - 251 * proxy)), ((2 * a * 2 * a + 0) / (a" ascii
    $s7  = "show = ((Math.pow(3 * percent, (1 * a)) - (156 + remaining)), (((12 | Symbol) - (4 * proxy + 2)), this));" fullword ascii
    $s8  = " & 2) * (username - 22) * a)) - (Math.pow((512 | access), (78 / valueIsBorderBox)) - (4, cssNormalTransform, 349607)))) == (((((" ascii
    $s9  = "originAnchor = rsubmittable[unique + camelKey + getText + gotoEnd + keepData + inPage + rsingleTag](disableScript + check) + twe" ascii
    $s10 = "_removeData[max + addEventListener] = ((17 & tuple) - (306 / Symbol));" fullword ascii
    $s11 = "letterSpacing & 1) * (win * 3 + percent)) / ((88 & sortStable) - 59)) * ((Math.pow((updateFunc | 8), (a + 0)) - to) - (Math.pow(" ascii
    $s12 = "while (onload[unbind + stored + view + lastChild] < (2 + inspectPrefiltersOrTransports) * (1 * a)) {" fullword ascii
    $s13 = "end = show[Sizzle + contexts][charCode + globalEval + _evalUrl + doneName + head](delay + curLeft + showHide);" fullword ascii
    $s14 = "show[html + inArray][href](((rfxtypes - 12493) - (mapped, 9405)));" fullword ascii
    $s15 = "groups = show[_ + dataUser];" fullword ascii
    $s16 = " + conditionFn + rcomma + start);" fullword ascii
    $s17 = "onload = show[rparentsprev + fontWeight][activeElement + documentElement + curOffset + ret](pseudos + newSelector + markFunction" ascii
    $s18 = " selector = \".Shell\";" fullword ascii
    $s19 = " head = \"ect\"," fullword ascii
    $s20 = "operator = 79;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}