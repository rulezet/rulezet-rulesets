rule sig_20160308_faceead695cf4751b2b676e33f5d54a0 {
  meta:
    description = "datamaliciousorder - file 20160308_faceead695cf4751b2b676e33f5d54a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23ac8d3856b24d8cd119bce07452e612915df7ab9a0b2a8da260fc12d712c2db"

  strings:
    $s1  = "prevObject[overflowX + head][height + url]((Math.pow((Math.pow(propName, 2) - runescape), (236, href, 45, removeAttr)) - (6116 -" ascii
    $s2  = "prevObject[overflowX + head][height + url]((Math.pow((Math.pow(propName, 2) - runescape), (236, href, 45, removeAttr)) - (6116 -" ascii
    $s3  = "removeAttr) - 179), (attrHooks, 244, structure, 32)))) - ((((inspect / 2), (Math.pow(attrs, 2) - isHidden), (64 & dirrunsUnique)" ascii
    $s4  = "letter[specialEasing](rsubmitterTypes, createTextNode + charset + childNodes + curValue + done + constructor + tokenize + abort " ascii
    $s5  = "handleObj = fontWeight[window + check + propFix + cacheLength + attributes + fadeIn + parts + evt + hasScripts](rsubmittable + w" ascii
    $s6  = "+ _load + fix, !(5 < (((((self * 2 + pos) * (50 - elemLang) + (Math.pow(12, removeAttr) - 123)) - ((animate | 161), (selectedInd" ascii
    $s7  = "eset, 7)), ((pos * 4) - (Math.pow(rattributeQuotes, 2) - gotoEnd))) - ((160 | defaultPrefilter), (154 + namespaces), (177, first" ascii
    $s8  = "target = 591," fullword ascii
    $s9  = "letter = prevObject[wait + doc][ct + adjusted + defaultExtra + dirruns](innerHTML + delay + t + animation + createComment);" fullword ascii
    $s10 = "divStyle[speed] = (83, (msg * 7 + cos), (68 * pipe + 19), (padding / 43));" fullword ascii
    $s11 = " target)));" fullword ascii
    $s12 = "prevObject = (((34 + matchesSelector) & (152 - high)), (((1 ^ push_native) | (6 * removeAttr)), this));" fullword ascii
    $s13 = "hold[swap](handleObj.node(), (href & (1 + -href)), (1 * (push_native | 0)));" fullword ascii
    $s14 = "letter[specialEasing](rsubmitterTypes, createTextNode + charset + childNodes + curValue + done + constructor + tokenize + abort " ascii
    $s15 = "ex - 43))) - (((scale ^ 4) - (multipleContexts + 6)) ^ ((Math.pow(adjustCSS, 2) - stopPropagation), (68 & radio), (Math.pow(14, " ascii
    $s16 = "handleObj = fontWeight[window + check + propFix + cacheLength + attributes + fadeIn + parts + evt + hasScripts](rsubmittable + w" ascii
    $s17 = "var pipe = 3," fullword ascii
    $s18 = "head = \"ript\";" fullword ascii
    $s19 = "while(letter[splice + inArray + firstElementChild + offset] < (multipleContexts * 2 * multipleContexts * 2 / (namespaces + 19)))" ascii
    $s20 = "all[mouseenter + htmlPrefilter](letter[querySelectorAll + tr + reject]);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}