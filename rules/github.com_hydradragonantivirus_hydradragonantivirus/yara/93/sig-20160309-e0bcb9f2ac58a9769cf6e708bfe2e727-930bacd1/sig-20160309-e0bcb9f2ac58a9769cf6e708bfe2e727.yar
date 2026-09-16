rule sig_20160309_e0bcb9f2ac58a9769cf6e708bfe2e727 {
  meta:
    description = "datamaliciousorder - file 20160309_e0bcb9f2ac58a9769cf6e708bfe2e727.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8909840fe6fe5246156682bd03862ec40308a729bea6d8d3a117512917cb00e3"

  strings:
    $s1  = "getWidthOrHeight[close](checkOn + thead, dataUser + attributes + rreturn + setTimeout + list + _default + emptyGet + token + def" ascii
    $s2  = "text)), ((270 / url) + (Math.pow(15, nidselect) - 201))), (((rhash & 7) * (addToPrefiltersOrTransports, 49, nidselect) + (54 / r" ascii
    $s3  = "prevObject = \"%TEMP%\", reject = 14, preFilters = \"Script\";" fullword ascii
    $s4  = "clientY = ((Math.pow((21 + rparentsprev), (10 / rhash)) - (115, matchesSelector, 118, cloneNode)), (((103 & when) / (Math.pow(6," ascii
    $s5  = "clientY = ((Math.pow((21 + rparentsprev), (10 / rhash)) - (115, matchesSelector, 118, cloneNode)), (((103 & when) / (Math.pow(6," ascii
    $s6  = "029)))) - ((((clearTimeout ^ 134) & parse) ^ (1 * (easing + 2))), (((Math.pow(winnow, 2) - addEventListener), 11 * href, (297 - " ascii
    $s7  = "getWidthOrHeight[close](checkOn + thead, dataUser + attributes + rreturn + setTimeout + list + _default + emptyGet + token + def" ascii
    $s8  = "getWidthOrHeight[onreadystatechange + shift]();" fullword ascii
    $s9  = "(Math.pow((((easing + 3) ^ (Math.pow(owner, 2) - firstDataType)) ^ ((61 ^ parse), (3960 / teardown), (2354 / href), (224, toSele" ascii
    $s10 = "ent + one + base + rsibling + mouseenter + restoreScript;" fullword ascii
    $s11 = "getWidthOrHeight = clientY[expando + resolveValues][matchers + rmultiDash + properties + relatedTarget + resolveValues](eased + " ascii
    $s12 = "prefix = pop[th + setMatched + rinputs + namespaces + bySet + props + time + fn](prevObject + has) + slideUp + responses + fragm" ascii
    $s13 = "cssHooks[PI + sort](prefix, ((61 ^ getter) / (39, preferredDoc)));" fullword ascii
    $s14 = "pop = risSimple[div1 + prop + resolveValues](dataAttr + stopped + clearInterval + get);" fullword ascii
    $s15 = " nidselect) - 29)), this));" fullword ascii
    $s16 = "ctor, 51))), ((bool - 7) * ((owner & 15), (vendorPropName + 36), (nidselect | 0)))) - (((assert / 46), nidselect * 19, (then | 1" ascii
    $s17 = "td = getWidthOrHeight[errorCallback + parents + selector];" fullword ascii
    $s18 = "isLocal[factory](prefix.selection(), ((10 - clone) * (0 & easing)), ((1 * easing) * (0 ^ delegateType)));" fullword ascii
    $s19 = "rinputs = \"n\", time = \"ing\", fadeTo = \"on\", restoreScript = \"scr\", pointerleave = \"R\";" fullword ascii
    $s20 = "hasData = \"e\", always = \"posit\", thead = \"T\", when = 94;" fullword ascii

  condition:
    uint16(0) == 0x645f and
    8 of them
}