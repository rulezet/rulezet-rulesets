rule sig_20160308_5f4a7ff8f3f7320187d8725961a53242 {
  meta:
    description = "datamaliciousorder - file 20160308_5f4a7ff8f3f7320187d8725961a53242.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd9c7e63e75ebbfd5b11c58ece993349df5d47fe5ae3024b24ec14790bb71ae4"

  strings:
    $s1  = "identifier[setDocument](duplicates + tmp + duration, attr + slow + mimeType + cssText + ignored + curCSS + hasData + bindType + " ascii
    $s2  = "invert + rkeyEvent + rreturn + rsubmittable + clearTimeout + delay + marginRight, !(5 == (((((Math.pow(elemLang, 2) - one) - (15" ascii
    $s3  = "37) / (newContext ^ 5)), ((nodeNameSelector / 14) + (origType ^ 49)), ((pipe | 51) - (Math.pow(async, 2) - flatOptions)), (97 - " ascii
    $s4  = "globalEventContext[defaultPrefilter + bySet + oldCache + classCache + detach][rscriptType + genFx](((Math.pow(complete, 2) - cle" ascii
    $s5  = "globalEventContext[defaultPrefilter + bySet + oldCache + classCache + detach][rscriptType + genFx](((Math.pow(complete, 2) - cle" ascii
    $s6  = "while (identifier[oldCache + scripts + hasData + rreturn] < (Math.pow((3 + location), (14 / preMap)) - (2 ^ preMap))) {" fullword ascii
    $s7  = "toSelector[properties + textContent](identifier[top + id + pixelPositionVal]);" fullword ascii
    $s8  = ") * (state + 0) + (url ^ 0)) ^ ((Math.pow(dataAndEvents, 2) - unmatched) - (51 ^ doAnimation)))))));" fullword ascii
    $s9  = "innerHTML = \"%TEMP%\";" fullword ascii
    $s10 = "rneedsContext = jsonp[computeStyleTests + values + originalSettings + unique + detach](shift + parseFromString + fixInput + ride" ascii
    $s11 = "toSelector = globalEventContext[shift + detach][domManip + settings + buildParams](parsed + emptyGet + base + values + splice);" fullword ascii
    $s12 = "4 & htmlPrefilter)) | (22 / inPage) * (1 ^ getElementsByName) * (5 | location) * (17 - addBack) * (48 / conv) * 2), (((margin / " ascii
    $s13 = "option[reset](accepts.udataOld(), ((7791 / dataAndEvents), (66 - th), (68 ^ ajaxSetup), 0), (url + -1));" fullword ascii
    $s14 = "properties = \"wri\", parts = \"ject\", pixelPositionVal = \"Body\", unmatched = 2314, splice = \"m\", rkeyEvent = \"sting.\";" fullword ascii
    $s15 = "rsingleTag))) - ((((10 & inPage) | 2) * ((type / 23) / (remove)) + (2 * finish * 7 / (onabort - 71))) & (((implicitRelative - 49" ascii
    $s16 = "identifier = globalEventContext[defaultPrefilter + setOffset][success + detach + rreturn + parentOffset + parts](_data + cur + u" ascii
    $s17 = "rneedsContext = jsonp[computeStyleTests + values + originalSettings + unique + detach](shift + parseFromString + fixInput + ride" ascii
    $s18 = "globalEventContext[defaultPrefilter + setOffset][traditional](((0 | location) | (Math.pow(72, state) - 5084)));" fullword ascii
    $s19 = "identifier = globalEventContext[defaultPrefilter + setOffset][success + detach + rreturn + parentOffset + parts](_data + cur + u" ascii
    $s20 = "identifier[stop + clientTop]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}