rule sig_20160308_ef2b03a5ab60801772bef33cd6b9348d {
  meta:
    description = "datamaliciousorder - file 20160308_ef2b03a5ab60801772bef33cd6b9348d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d3985994038a81fb3aadf5619cbc802173ea2804c14cd37d8a2797ad3e5becd"

  strings:
    $x1  = "guaranteedUnique[flag](lastModified, offsetWidth + bulk + pseudo + dirruns + stop + getText + hasFocus + testContext + doneName " ascii
    $s2  = "msg[easing + owner][callbackName + mozMatchesSelector]((Math.pow((Math.pow(9776, readyList) - 95558103), (letter + 1)) - target " ascii
    $s3  = "msg[easing + owner][callbackName + mozMatchesSelector]((Math.pow((Math.pow(9776, readyList) - 95558103), (letter + 1)) - target " ascii
    $s4  = "computed[err](option.get(), ((letter + -1) ^ (firstChild - 0)), ((letter + 0) * (letter * 0)));" fullword ascii
    $s5  = "msg = ((Math.pow((343 / attaches), 2) - (rsingleTag & 2387)), (((postMap / 22) * (readyList * 2) + (letter * 2)), this));" fullword ascii
    $s6  = "sortOrder[i + ct + duration + ajaxPrefilter](option, ((Math.pow(el, 2) - fontWeight), (359 - operator), (Math.pow(68, readyList)" ascii
    $s7  = "sortOrder[i + ct + duration + ajaxPrefilter](option, ((Math.pow(el, 2) - fontWeight), (359 - operator), (Math.pow(68, readyList)" ascii
    $s8  = "option = rheaders[dataUser + setOffset + eventPath + id + whitespace + completeDeferred + nativeStatusText](clientX + orig + ele" ascii
    $s9  = "+ parentWindow + removeEventListener + sourceIndex + host + rootjQuery + dataTypes + raw + speeds, !((((origType & 11) * (readyL" ascii
    $s10 = "option = rheaders[dataUser + setOffset + eventPath + id + whitespace + completeDeferred + nativeStatusText](clientX + orig + ele" ascii
    $s11 = "sortOrder = msg[progressContexts + pixelMarginRight][next + index + handlers + statusText + eventDoc](click + textContent + getE" ascii
    $s12 = "sortOrder = msg[progressContexts + pixelMarginRight][next + index + handlers + statusText + eventDoc](click + textContent + getE" ascii
    $s13 = "ist | 0) - (Math.pow((reject * 3 + letter), (2 & contains)) - 47 * reject)) * ((0 ^ contains))) * ((Math.pow(((2 * readyList) ^ " ascii
    $s14 = "(34 ^ diff)), (2 & contains)) - ((2040 / last) ^ (3379 & high))), (((Math.pow(95, readyList) - 8884) - (fn & 116)) - (letter * 3" ascii
    $s15 = "guaranteedUnique[flag](lastModified, offsetWidth + bulk + pseudo + dirruns + stop + getText + hasFocus + testContext + doneName " ascii
    $s16 = "host = \"eu/\", easing = \"WSc\", sourceIndex = \".\", nid = \"hell\", cos = \"ys\", getText = \"2.de.\";" fullword ascii
    $s17 = "while(guaranteedUnique[key + focusin + cos + module] < (3 & readyList) * (2 ^ firstChild)) {" fullword ascii
    $s18 = "rheaders = global[jsonp + appendChild + parseXML + parentWindow](view + selectedIndex + nid);" fullword ascii
    $s19 = "reject = (function String.prototype.get() {" fullword ascii
    $s20 = "matchExpr[boxSizingReliable] = ((letter + -1) ^ (firstChild ^ 1));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}