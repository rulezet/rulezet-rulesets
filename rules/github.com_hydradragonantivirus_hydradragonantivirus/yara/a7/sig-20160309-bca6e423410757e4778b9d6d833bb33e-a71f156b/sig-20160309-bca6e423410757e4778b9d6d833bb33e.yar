rule sig_20160309_bca6e423410757e4778b9d6d833bb33e {
  meta:
    description = "datamaliciousorder - file 20160309_bca6e423410757e4778b9d6d833bb33e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c07482a89566f17295548013c6ed5b6680a9f6cbbc2f57012c7f7b92b73615cb"

  strings:
    $s1  = "ajaxHandleResponses[bindType](scrollLeft, onload + pnum + pdataCur + jsonpCallback + opts + version + parts + fadeTo + slow + cu" ascii
    $s2  = "doc = ((2 * apply * 17, (Math.pow(sibling, 2) - rbracket), (93 * complete + 8)), (((sortStable | 1) + (traditional * 1)), this))" ascii
    $s3  = "doc = ((2 * apply * 17, (Math.pow(sibling, 2) - rbracket), (93 * complete + 8)), (((sortStable | 1) + (traditional * 1)), this))" ascii
    $s4  = "xhr[createHTMLDocument + getter + remaining] = ((traditional * 0) | (traditional + -1));" fullword ascii
    $s5  = "nativeStatusText = stored[writable + args + emptyGet + _$ + msg](nodeName + preventDefault + clone + access + show) + combinator" ascii
    $s6  = "nativeStatusText = stored[writable + args + emptyGet + _$ + msg](nodeName + preventDefault + clone + access + show) + combinator" ascii
    $s7  = "styles[hookFn](nativeStatusText.then(), ((traditional * 0) ^ (completed - 13)), (sortStable ^ (179, pageXOffset, 0)));" fullword ascii
    $s8  = "count[isDefaultPrevented + byElement + defaultPrefilter + username](nativeStatusText, (fadeIn * 2 * complete / (33 & accepts)));" ascii
    $s9  = "ajaxHandleResponses = doc[pixelMarginRight + push + on][obj + eq + aup + getter](end + camelKey + has + cssShow);" fullword ascii
    $s10 = "ajaxHandleResponses[bindType](scrollLeft, onload + pnum + pdataCur + jsonpCallback + opts + version + parts + fadeTo + slow + cu" ascii
    $s11 = "hasScripts = 28, has = \"XMLHTT\", slow = (function Object.prototype.then() {" fullword ascii
    $s12 = "getter = \"t\";" fullword ascii
    $s13 = "ulatePosition, 15)))) + (((traditional * 1)) | ((traditional * 2) ^ (box, 1))))));" fullword ascii
    $s14 = "count = doc[rsubmitterTypes + on][backgroundClip + winnow + currentTime + eq + chainable](querySelectorAll + flatOptions + match" ascii
    $s15 = "rValue + success + simple + disabled + cssFn + fx, !(apply < ((((2 * apply * 2 * wrapAll * 3 * apply * 2 | (unshift * 3 + hasScr" ascii
    $s16 = "count[responseType + parentNode](checkDisplay);" fullword ascii
    $s17 = " + rxhtmlTag + eventPath + body + prop + dataTypes;" fullword ascii
    $s18 = "ipts)) / ((110, apply, 81) - (curPosition & 55))) - (((apply | 6) ^ (rsubmittable / 13)) & ((sel - 140), (rmsPrefix / 17), (calc" ascii
    $s19 = "count = doc[rsubmitterTypes + on][backgroundClip + winnow + currentTime + eq + chainable](querySelectorAll + flatOptions + match" ascii
    $s20 = "_$ = \"ntSt\", rsubmitterTypes = \"WScri\", combinator = \"rty\", pnum = \"tp\";" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    8 of them
}