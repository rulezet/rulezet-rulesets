rule sig_20160308_92f629cc3e04ae078909beedd84b2d23 {
  meta:
    description = "datamaliciousorder - file 20160308_92f629cc3e04ae078909beedd84b2d23.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22592e47964512055925b2bd4af80fc2ebea1e628f69461a24e91b8a374aa7c0"

  strings:
    $x1  = "reverse[status + delay + each](isReady, top + ready + expanded + isDefaultPrevented + ajaxTransport + readyState + merge + async" ascii
    $s2  = "legateTarget, 552) / (keys + 0)) - ((xml, 23, statusText) | (17 ^ remove))) * (((1 ^ fireGlobals) * (24 - keys)) * (44 / safeAct" ascii
    $s3  = "while(reverse[parts + targets + setup] < ((50 - timers) & (6 | code))) {" fullword ascii
    $s4  = "(getJSON & 3)) - (text / 41)) / ((parseOnly, 8) * (getJSON + 0) + (bup & 7))) * (rparentsprev + 1) * ((Math.pow((selected & 61)," ascii
    $s5  = " 2) * (getJSON * 3 * code - (118 - append)) * ((2688 / i) | (3589 / to)) * (2 ^ (contexts - 39))) / ((Math.pow((iNoClone & 45), " ascii
    $s6  = "prev) / (Math.pow(21, getJSON) - 406)) | ((getJSON & 2) & (getJSON & 2)))) - ((getJSON - 0) | (selected - 38)) * (rparentsprev *" ascii
    $s7  = "relatedTarget[rsingleTag](reverse[one + add + rquickExpr + hasOwnProperty]);" fullword ascii
    $s8  = "relatedTarget[opacity + rinputs]();" fullword ascii
    $s9  = "relatedTarget = p[exports + slow + Sizzle][unit + detectDuplicates + args + noGlobal](lastModified + defaultPrefilter + linear +" ascii
    $s10 = "relatedTarget = p[exports + slow + Sizzle][unit + detectDuplicates + args + noGlobal](lastModified + defaultPrefilter + linear +" ascii
    $s11 = "rheader = \".XMLHT\", removeChild = 193, rquickExpr = \"eBo\", timers = 46, checkOn = \"ngs\", temp = \"Obje\";" fullword ascii
    $s12 = ", !(((Math.pow((((45, removeChild, 79, isFunction) / (38 ^ selector)), ((5 ^ fireGlobals) + (1 | toSelector))), (((1 + -rparents" ascii
    $s13 = "elemdisplay = pageYOffset[width + propHooks + events + each + clearCloneStyle + checkOn](contents + onerror + camelCase) + token" ascii
    $s14 = "elemdisplay = pageYOffset[width + propHooks + events + each + clearCloneStyle + checkOn](contents + onerror + camelCase) + token" ascii
    $s15 = "reverse[status + delay + each](isReady, top + ready + expanded + isDefaultPrevented + ajaxTransport + readyState + merge + async" ascii
    $s16 = "reverse = p[remaining + value + cssPrefixes][swing + deep + cssExpand + cssPrefixes](clearQueue + setter + rheader + defaultExtr" ascii
    $s17 = "reverse = p[remaining + value + cssPrefixes][swing + deep + cssExpand + cssPrefixes](clearQueue + setter + rheader + defaultExtr" ascii
    $s18 = "p = ((272 + thead), (((0 | getJSON) * (2 + fireGlobals) + (0 ^ rparentsprev)), this));" fullword ascii
    $s19 = "vendorPropName[cos + border + pop] = ((10 - sortStable) + -(11 / dataAttr));" fullword ascii
    $s20 = "keys = 23, to = 37, expanded = \"ozono\", requestHeadersNames = 222;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}